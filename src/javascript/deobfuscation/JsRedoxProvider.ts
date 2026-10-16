import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, realpath, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { TextDecoder } from "node:util";
import type { JavaScriptDeobfuscationPort } from "../../application/javascript/JavaScriptDeobfuscationPort.js";
import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../../application/AnalysisProvider.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { SafeOutputTreeCreationFailure } from "../../artifacts/SafeOutputTreeCreationFailure.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";
import type { JavaScriptDeobfuscationInput } from "../../domain/javascript/javascriptDeobfuscation.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  prlimitArgumentVector,
  readLinuxResourceLimits,
} from "../../process/LinuxResourceLimits.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../../process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import type { ProviderProcessSupervisor } from "../../process/ProviderProcess.js";
import {
  executeJsRedox,
  remainingJsRedoxTimeoutMs,
  type JsRedoxEngine,
  type JsRedoxRunRequest,
  type JsRedoxRunResult,
} from "./JsRedoxExecution.js";
import {
  JS_REDOX_LIMITS,
  JS_REDOX_PROVIDER_IDENTITY,
} from "./JsRedoxRelease.js";

const OPERATION = "deobfuscate_javascript_source";
const HOST_REQUIREMENT =
  "On Linux x64, provide an absolute REA_JS_REDOX_COMMAND pointing to js-redox deobfuscate-safe 0.1.0, util-linux prlimit, and an executable private runtime filesystem (TMPDIR must not be mounted noexec).";

export type JsRedoxLauncher = NonNullable<
  Parameters<typeof runOwnedCommand>[2]
>["launcher"];

type PendingCleanup = {
  root: Pick<PrivateRuntimeRoot, "path" | "close"> | undefined;
  process: ProviderProcessSupervisor | undefined;
  tree: SafeOutputTree | undefined;
};

/** Caller-supplied js-redox adapter for proof-gated static JavaScript rewriting. */
export class JsRedoxProvider implements JavaScriptDeobfuscationPort {
  readonly #resources = new ArtifactResourceScope();
  #tail: Promise<void> = Promise.resolve();
  #closing = false;
  #closePromise: Promise<void> | undefined;
  #pendingCleanup: PendingCleanup | undefined;

  constructor(
    readonly environment: Readonly<NodeJS.ProcessEnv> = process.env,
    readonly launcher?: JsRedoxLauncher,
    readonly createRuntime: () => Promise<
      Pick<PrivateRuntimeRoot, "path" | "close">
    > = () => {
      const parent = runtimeParent(environment);
      return PrivateRuntimeRoot.create({
        prefix: "rea-js-redox-",
        ...(parent === undefined ? {} : { parent }),
      });
    },
  ) {}

  deobfuscate(
    input: JavaScriptDeobfuscationInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (this.#closing) return Promise.resolve(err(this.#closedError()));
    const operation = this.#tail.then(() =>
      this.#closing
        ? err(this.#closedError())
        : this.#deobfuscate(input, options),
    );
    this.#tail = operation.then(
      () => undefined,
      () => undefined,
    );
    return operation;
  }

  async #deobfuscate(
    input: JavaScriptDeobfuscationInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    try {
      await this.#resources.retryCleanup();
    } catch (cause: unknown) {
      return err(
        new ProviderCleanupError(
          JS_REDOX_PROVIDER_IDENTITY.id,
          ["js-redox artifact handles"],
          { reason: failureMessage(cause) },
          { operation: OPERATION, cause },
        ),
      );
    }
    const pending = await this.#retire();
    if (pending !== undefined) return err(pending);
    let root: Pick<PrivateRuntimeRoot, "path" | "close"> | undefined;
    let tree: SafeOutputTree | undefined;
    let processOwner: ProviderProcessSupervisor | undefined;
    let execution: AnalysisExecution | undefined;
    let failure: unknown;
    try {
      if (options?.signal?.aborted) throw new AnalysisCancelledError(OPERATION);
      const engine = await this.#resolveEngine(options?.signal);
      const source = await this.#readInput(input.path, options?.signal);
      root = await this.createRuntime();
      try {
        tree = await SafeOutputTree.create(input.output_directory);
      } catch (cause: unknown) {
        if (cause instanceof SafeOutputTreeCreationFailure) tree = cause.tree;
        throw new AnalysisInputError(OPERATION, { cause }, [
          {
            path: ["output_directory"],
            reason: "invalid_value",
            message: `Cannot create new deobfuscation directory ${input.output_directory}: ${failureMessage(cause)}`,
          },
        ]);
      }
      execution = await executeJsRedox({
        request: input,
        ...(options?.signal === undefined ? {} : { signal: options.signal }),
        engine,
        source,
        runtimePath: root.path,
        tree,
        resourceScope: this.#resources,
        run: (request) => this.#run(engine, request),
      });
      await root.close();
      root = undefined;
      if (options?.signal?.aborted) throw new AnalysisCancelledError(OPERATION);
      await tree.commit(options?.signal);
    } catch (cause: unknown) {
      failure = cause;
      if (cause instanceof OwnedCommandFailure)
        processOwner = cause.cleanupOwner;
    }
    if (failure === undefined)
      return execution === undefined
        ? err(
            new AnalysisOutputError(
              OPERATION,
              "Deobfuscation returned no execution",
            ),
          )
        : ok(execution);

    return this.#handleFailure({
      failure,
      root,
      tree,
      processOwner,
      execution,
      signal: options?.signal,
    });
  }

  async #handleFailure(state: {
    readonly failure: unknown;
    readonly root: Pick<PrivateRuntimeRoot, "path" | "close"> | undefined;
    readonly tree: SafeOutputTree | undefined;
    readonly processOwner: ProviderProcessSupervisor | undefined;
    readonly execution: AnalysisExecution | undefined;
    readonly signal: AbortSignal | undefined;
  }): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (state.tree?.published === true && state.execution !== undefined) {
      if (
        state.processOwner !== undefined ||
        state.tree !== undefined ||
        state.root !== undefined
      ) {
        this.#pendingCleanup = {
          root: state.root,
          process: state.processOwner,
          tree: state.tree,
        };
        return ok({
          ...state.execution,
          limitations: [
            ...state.execution.limitations,
            `Output was published, but provider cleanup remains incomplete: ${failureMessage(state.failure)}`,
          ],
        });
      }
      return ok(state.execution);
    }
    let failedTree: SafeOutputTree | undefined;
    if (state.tree !== undefined) {
      try {
        await state.tree.rollback();
      } catch {
        failedTree = state.tree;
      }
    }
    let failedRoot = state.root;
    if (failedRoot !== undefined && state.processOwner === undefined) {
      try {
        await failedRoot.close();
        failedRoot = undefined;
      } catch {
        // Retain ownership for close() retry below.
      }
    }
    if (
      state.processOwner !== undefined ||
      failedTree !== undefined ||
      failedRoot !== undefined
    ) {
      this.#pendingCleanup = {
        root: failedRoot,
        process: state.processOwner,
        tree: failedTree,
      };
      return err(
        this.#cleanupError(
          state.failure,
          failedRoot,
          failedTree,
          state.processOwner,
        ),
      );
    }
    return err(this.#projectFailure(state.failure, state.signal));
  }

  #cleanupError(
    failure: unknown,
    root: Pick<PrivateRuntimeRoot, "path" | "close"> | undefined,
    tree: SafeOutputTree | undefined,
    processOwner: ProviderProcessSupervisor | undefined,
  ): ProviderCleanupError {
    return new ProviderCleanupError(
      JS_REDOX_PROVIDER_IDENTITY.id,
      [
        ...(processOwner === undefined
          ? []
          : [processOwner.launch.ownership?.runId ?? "js-redox-worker"]),
        ...(tree === undefined ? [] : [tree.outputRoot]),
        ...(root === undefined ? [] : [root.path]),
      ],
      { previous_error: failureMessage(failure) },
      { operation: OPERATION, cause: failure },
    );
  }

  async #resolveEngine(signal?: AbortSignal): Promise<JsRedoxEngine> {
    const configured = this.environment.REA_JS_REDOX_COMMAND;
    const configuredLimiter =
      this.environment.REA_JAVASCRIPT_PRLIMIT_COMMAND ?? "/usr/bin/prlimit";
    if (
      process.platform !== "linux" ||
      process.arch !== "x64" ||
      configured === undefined ||
      !isAbsolute(configured) ||
      !isAbsolute(configuredLimiter)
    )
      throw new AnalysisCapabilityUnavailableError(
        JS_REDOX_PROVIDER_IDENTITY.id,
        OPERATION,
        HOST_REQUIREMENT,
        { userMessage: HOST_REQUIREMENT },
      );
    try {
      const command = await realpath(configured);
      await access(command, constants.R_OK | constants.X_OK);
      const executable = await readStableArtifact(
        command,
        JS_REDOX_LIMITS.executableBytes,
        signal,
        undefined,
        this.#resources,
      );
      const limiterCommand = await realpath(configuredLimiter);
      await access(limiterCommand, constants.X_OK);
      const limiterExecutable = await readStableArtifact(
        limiterCommand,
        JS_REDOX_LIMITS.executableBytes,
        signal,
        undefined,
        this.#resources,
      );
      return {
        configuredCommand: configured,
        command,
        sha256: executable.sha256,
        bytes: executable.bytes.length,
        executable: executable.bytes,
        limiter: {
          configuredCommand: configuredLimiter,
          command: limiterCommand,
          sha256: limiterExecutable.sha256,
          bytes: limiterExecutable.bytes.length,
          executable: limiterExecutable.bytes,
        },
      };
    } catch (cause: unknown) {
      if (signal?.aborted) throw new AnalysisCancelledError(OPERATION);
      const reason = `Configured js-redox or util-linux prlimit is unavailable: ${failureMessage(cause)}`;
      throw new AnalysisCapabilityUnavailableError(
        JS_REDOX_PROVIDER_IDENTITY.id,
        OPERATION,
        reason,
        { cause, userMessage: reason },
      );
    }
  }

  async #readInput(path: string, signal?: AbortSignal) {
    try {
      const source = await readStableArtifact(
        path,
        JS_REDOX_LIMITS.inputBytes,
        signal,
        undefined,
        this.#resources,
      );
      new TextDecoder("utf-8", { fatal: true }).decode(source.bytes);
      return source;
    } catch (cause: unknown) {
      if (signal?.aborted) throw new AnalysisCancelledError(OPERATION);
      throw new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Cannot read stable UTF-8 JavaScript input ${path}: ${failureMessage(cause)}`,
        },
      ]);
    }
  }

  async #bindLimiter(
    engine: JsRedoxEngine,
    runtimePath: string,
    signal?: AbortSignal,
  ) {
    const limiter = join(runtimePath, `prlimit-${randomUUID()}`);
    await writeFile(limiter, engine.limiter.executable, {
      flag: "wx",
      mode: 0o700,
      ...(signal === undefined ? {} : { signal }),
    });
    try {
      await access(limiter, constants.X_OK);
    } catch (cause: unknown) {
      if (signal?.aborted) throw new AnalysisCancelledError(OPERATION);
      throw new AnalysisCapabilityUnavailableError(
        JS_REDOX_PROVIDER_IDENTITY.id,
        OPERATION,
        "The private resource-limiter snapshot is not executable. Select an exec-capable TMPDIR; noexec runtime mounts are unsupported.",
        {
          cause,
          userMessage:
            "Set TMPDIR to a writable exec-capable filesystem and retry.",
        },
      );
    }
    const snapshot = await readStableArtifact(
      limiter,
      JS_REDOX_LIMITS.executableBytes,
      signal,
      undefined,
      this.#resources,
    );
    if (
      snapshot.sha256 !== engine.limiter.sha256 ||
      snapshot.bytes.length !== engine.limiter.bytes
    )
      throw new AnalysisOutputError(
        OPERATION,
        "Owned resource-limiter snapshot disagrees with the fingerprinted executable bytes.",
      );
    return {
      command: limiter,
      sha256: snapshot.sha256,
      bytes: snapshot.bytes.length,
    };
  }

  async #run(
    engine: JsRedoxEngine,
    request: JsRedoxRunRequest,
  ): Promise<JsRedoxRunResult> {
    const limiter = await this.#bindLimiter(
      engine,
      request.cwd,
      request.signal,
    );
    const limits = await readLinuxResourceLimits(
      {
        address_space_bytes: JS_REDOX_LIMITS.addressSpaceBytes,
        file_bytes: JS_REDOX_LIMITS.outputBytes,
        cpu_seconds: JS_REDOX_LIMITS.cpuSeconds,
      },
      this.#resources,
    );
    const limiterArguments = [
      ...prlimitArgumentVector(limits, request.command),
      ...request.arguments,
    ];
    const snapshot = await runOwnedCommand(
      {
        command: limiter.command,
        arguments: limiterArguments,
        expectedCommand: null,
        runId: `rea-js-redox-${randomUUID()}`,
        cwd: request.cwd,
        hostEnvironment: this.environment,
        env: { TMPDIR: request.cwd, RAYON_NUM_THREADS: "1", NO_COLOR: "1" },
      },
      {
        timeoutMs: remainingJsRedoxTimeoutMs(request.deadlineAt),
        diagnosticBytes: JS_REDOX_LIMITS.diagnosticBytes,
      },
      {
        ...(request.signal === undefined ? {} : { signal: request.signal }),
        ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
      },
    );
    return {
      snapshot,
      limiter: {
        snapshotPath: limiter.command,
        snapshotSha256: limiter.sha256,
        snapshotBytes: limiter.bytes,
        arguments: limiterArguments,
      },
    };
  }

  #projectFailure(cause: unknown, signal?: AbortSignal): AnalysisError {
    if (cause instanceof AnalysisError) return cause;
    if (signal?.aborted)
      return new AnalysisCancelledError(OPERATION, { cause });
    if (cause instanceof OwnedCommandFailure) {
      if (cause.reason === "cancelled")
        return new AnalysisCancelledError(OPERATION, { cause });
      if (cause.reason === "timeout")
        return new AnalysisTimeoutError(OPERATION, JS_REDOX_LIMITS.timeoutMs, {
          cause,
        });
      const resource =
        cause.reason === "output-limit"
          ? "capacity"
          : cause.snapshot?.signal === "SIGXCPU"
            ? "cpu"
            : cause.snapshot?.signal === "SIGXFSZ"
              ? "file-size"
              : undefined;
      if (resource !== undefined)
        return new AnalysisResourceConstraintError(
          OPERATION,
          resource,
          resource === "capacity"
            ? "Owned worker exceeded the bounded diagnostic output capacity."
            : `Owned worker exited with ${cause.snapshot?.signal}; consistent with the configured ${resource} limit, but the signal alone does not prove limit enforcement.`,
          {
            diagnostic_bytes_ceiling: JS_REDOX_LIMITS.diagnosticBytes,
            cpu_seconds_ceiling: JS_REDOX_LIMITS.cpuSeconds,
            file_bytes_ceiling: JS_REDOX_LIMITS.outputBytes,
          },
          { cause, diagnostics: ownedCommandDiagnostics(cause) },
        );
    }
    return new ProviderAdapterError(JS_REDOX_PROVIDER_IDENTITY.id, OPERATION, {
      cause,
      diagnostics:
        cause instanceof OwnedCommandFailure
          ? ownedCommandDiagnostics(cause)
          : { reason: failureMessage(cause) },
    });
  }

  #closedError(): ProviderCleanupError {
    return new ProviderCleanupError(
      JS_REDOX_PROVIDER_IDENTITY.id,
      [],
      { reason: "Provider is closing" },
      { operation: OPERATION },
    );
  }

  async close(): Promise<void> {
    this.#closing = true;
    this.#closePromise ??= this.#tail
      .then(async () => {
        const failure = await this.#retire();
        if (failure !== undefined) throw failure;
        try {
          await this.#resources.close();
        } catch (cause: unknown) {
          throw new ProviderCleanupError(
            JS_REDOX_PROVIDER_IDENTITY.id,
            ["js-redox artifact handles"],
            { reason: failureMessage(cause) },
            { operation: OPERATION, cause },
          );
        }
      })
      .catch((cause: unknown) => {
        this.#closePromise = undefined;
        throw cause;
      });
    return this.#closePromise;
  }

  async #retire(): Promise<ProviderCleanupError | undefined> {
    const pending = this.#pendingCleanup;
    if (pending === undefined) return undefined;
    if (pending.process !== undefined) {
      const stopped = await pending.process.stop();
      if (stopped.status === "incomplete")
        return new ProviderCleanupError(
          JS_REDOX_PROVIDER_IDENTITY.id,
          [pending.process.launch.ownership?.runId ?? "js-redox-worker"],
          { reason: stopped.reason },
          { operation: OPERATION },
        );
      pending.process = undefined;
    }
    if (pending.tree !== undefined) {
      const tree = pending.tree;
      try {
        await tree.rollback();
        pending.tree = undefined;
      } catch (cause: unknown) {
        return new ProviderCleanupError(
          JS_REDOX_PROVIDER_IDENTITY.id,
          [tree.outputRoot],
          { reason: failureMessage(cause) },
          { operation: OPERATION, cause },
        );
      }
    }
    if (pending.root !== undefined) {
      const runtime = pending.root;
      try {
        await runtime.close();
        pending.root = undefined;
      } catch (cause: unknown) {
        return new ProviderCleanupError(
          JS_REDOX_PROVIDER_IDENTITY.id,
          [runtime.path],
          { reason: failureMessage(cause) },
          { operation: OPERATION, cause },
        );
      }
    }
    this.#pendingCleanup = undefined;
    return undefined;
  }
}

const runtimeParent = (
  environment: Readonly<NodeJS.ProcessEnv>,
): string | undefined => {
  const configured = environment.TMPDIR?.trim();
  return configured === undefined || configured.length === 0
    ? undefined
    : resolve(configured);
};

const ownedCommandDiagnostics = (
  failure: OwnedCommandFailure,
): Readonly<Record<string, import("../../domain/jsonValue.js").JsonValue>> => ({
  reason: failure.message,
  exit_code: failure.snapshot?.exitCode ?? null,
  exit_signal: failure.snapshot?.signal ?? null,
  diagnostic_truncated: failure.snapshot?.diagnosticTruncated === true,
  stdout:
    failure.snapshot === null
      ? null
      : {
          text: failure.snapshot.stdout.text,
          bytes: failure.snapshot.stdout.observedBytes,
          retained_bytes: failure.snapshot.stdout.bytes,
        },
  stderr:
    failure.snapshot === null
      ? null
      : {
          text: failure.snapshot.stderr.text,
          bytes: failure.snapshot.stderr.observedBytes,
          retained_bytes: failure.snapshot.stderr.bytes,
        },
});

const failureMessage = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);
