import { realpath } from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";

import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  javascriptDeobfuscationInputSchema,
  javascriptDeobfuscationResultSchema,
} from "../../domain/javascript/javascriptDeobfuscation.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { absoluteCallerPath } from "../../filesystem/callerPath.js";
import type { JavaScriptDeobfuscationPort } from "./JavaScriptDeobfuscationPort.js";

const OPERATION = "deobfuscate_javascript_source";

/** Shared CLI/MCP validation and Evidence for proof-gated JavaScript rewriting. */
export class JavaScriptDeobfuscationService {
  constructor(readonly provider: JavaScriptDeobfuscationPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async deobfuscate(
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (isCancelled(options?.signal))
      return err(new AnalysisCancelledError(OPERATION));
    const parsed = javascriptDeobfuscationInputSchema.safeParse(input);
    if (!parsed.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, parsed.error.issues, input, {
          cause: parsed.error,
        }),
      );
    const invalidPaths = (["path", "output_directory"] as const).filter(
      (field) => !isAbsolute(parsed.data[field]),
    );
    if (invalidPaths.length > 0)
      return err(
        new AnalysisInputError(
          OPERATION,
          undefined,
          invalidPaths.map((field) => ({
            path: [field],
            reason: "invalid_format",
            message: `${field} must be an absolute filesystem path on this host.`,
          })),
        ),
      );
    let outputRoot: string;
    try {
      outputRoot = await canonicalAbsentOutputRoot(
        parsed.data.output_directory,
      );
    } catch (cause: unknown) {
      return err(
        new AnalysisInputError(
          OPERATION,
          {
            cause,
            userMessage:
              "The parent of output_directory must exist and be resolvable on this host.",
          },
          [
            {
              path: ["output_directory"],
              reason: "invalid_value",
              message:
                "The parent of output_directory must exist and be resolvable on this host.",
            },
          ],
        ),
      );
    }
    const execution = await this.provider.deobfuscate(parsed.data, options);
    if (!execution.ok) return execution;
    const result = javascriptDeobfuscationResultSchema.safeParse(
      execution.value.result,
    );
    if (!result.success || execution.value.subject === null)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Deobfuscation did not return a valid result bound to the original source",
        ),
      );
    const publishedPaths = [
      result.data.source.published_copy.path,
      result.data.output.path,
      result.data.report.path,
      result.data.manifest.path,
      result.data.analysis_input.input_path,
    ];
    if (
      result.data.source.path !== parsed.data.path ||
      result.data.source.published_copy.sha256 !== result.data.source.sha256 ||
      result.data.source.published_copy.bytes !== result.data.source.bytes ||
      result.data.proof.input_sha256 !== result.data.source.sha256 ||
      result.data.proof.output_sha256 !== result.data.output.sha256 ||
      execution.value.subject.path !== result.data.source.path ||
      execution.value.subject.sha256 !== result.data.source.sha256 ||
      result.data.options.max_iterations !== parsed.data.max_iterations ||
      (result.data.status === "unchanged") !==
        (result.data.source.sha256 === result.data.output.sha256) ||
      execution.value.subject.format !== "javascript" ||
      publishedPaths.some((path) => !isWithin(outputRoot, path))
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Deobfuscation source, published artifacts, output status, or iteration bound disagrees with its Evidence binding",
        ),
      );
    const evidence = createEvidence(
      execution.value.subject,
      execution.value.provider,
      {
        operation: OPERATION,
        parameters: jsonObjectSchema.parse(parsed.data),
        result: jsonObjectSchema.parse(result.data),
        ...(execution.value.rawResult === null
          ? {}
          : { rawResult: execution.value.rawResult }),
        locations: execution.value.locations,
        limitations: mergeLimitations(
          result.data.limitations,
          execution.value.limitations,
        ),
        confidence: "derived",
        authority: "shipped-artifact",
      },
    );
    if (isCancelled(options?.signal))
      return err(
        new AnalysisCancelledError(OPERATION, {
          partialObservation: evidence,
        }),
      );
    return ok(evidence);
  }
}

const isWithin = (root: string, path: string): boolean => {
  const candidate = resolve(path);
  const child = relative(root, candidate);
  return (
    child === "" ||
    (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`))
  );
};

const isCancelled = (signal?: AbortSignal): boolean => signal?.aborted === true;

const canonicalAbsentOutputRoot = async (
  requested: string,
): Promise<string> => {
  const absolute = absoluteCallerPath(requested);
  const parent = await realpath(dirname(absolute));
  return join(parent, basename(absolute));
};

const mergeLimitations = (
  normalized: readonly string[],
  execution: readonly string[],
): readonly string[] => [...new Set([...normalized, ...execution])];
