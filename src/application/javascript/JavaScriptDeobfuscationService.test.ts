import { mkdir, symlink } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";
import type { JavaScriptDeobfuscationResult } from "../../domain/javascript/javascriptDeobfuscation.js";
import { err, ok } from "../../domain/result.js";
import { createAnalysisExecution } from "../AnalysisProvider.js";
import { JavaScriptDeobfuscationService } from "./JavaScriptDeobfuscationService.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";

const file = { path: "/tmp/source.js", sha256: "a".repeat(64), bytes: 12 };
const outputFile = (path: string, outputRoot = "/tmp/out") => ({
  path: `${outputRoot}/${path}`,
  sha256: file.sha256,
  bytes: file.bytes,
});
const provider = {
  id: "fixture-deobfuscator",
  name: "Fixture deobfuscator",
  version: "1",
} as const;
const result = (outputRoot = "/tmp/out"): JavaScriptDeobfuscationResult => ({
  source: {
    ...file,
    published_copy: outputFile("inputs/source.js", outputRoot),
  },
  options: { max_iterations: 16 },
  status: "unchanged",
  output: outputFile("deobfuscated/source.js", outputRoot),
  report: outputFile("reports/js-redox.json", outputRoot),
  manifest: outputFile("manifest.json", outputRoot),
  proof: {
    input_sha256: file.sha256,
    output_sha256: file.sha256,
  },
  analysis_input: {
    input_path: `${outputRoot}/deobfuscated`,
    format: "directory",
  },
  runtime_execution: "not-performed",
  limitations: [],
});

describe("JavaScript deobfuscation workflow", () => {
  it.each(["changed", "unchanged"] as const)(
    "rejects %s status that contradicts source/output digests",
    async (status) => {
      const returned = result();
      returned.status = status;
      if (status === "unchanged") {
        returned.output = { ...returned.output, sha256: "b".repeat(64) };
      }
      const service = new JavaScriptDeobfuscationService({
        deobfuscate: async () =>
          ok(
            createAnalysisExecution(returned, provider, {
              subject: {
                path: file.path,
                sha256: file.sha256,
                format: "javascript",
              },
            }),
          ),
      });
      const response = await service.deobfuscate({
        path: file.path,
        output_directory: "/tmp/out",
      });
      if (response.ok) throw new Error("expected status binding rejection");
      expect(response.error._tag).toBe("AnalysisOutputError");
    },
  );
  it.each([64, 15])(
    "rejects provider options=%s for a requested bound of one",
    async (maximum) => {
      const returned = result();
      returned.options.max_iterations = maximum;
      const service = new JavaScriptDeobfuscationService({
        deobfuscate: async () =>
          ok(
            createAnalysisExecution(returned, provider, {
              subject: {
                path: file.path,
                sha256: file.sha256,
                format: "javascript",
              },
            }),
          ),
      });
      const response = await service.deobfuscate({
        path: file.path,
        output_directory: "/tmp/out",
        max_iterations: 1,
      });
      if (response.ok) throw new Error("expected iteration binding rejection");
      expect(response.error._tag).toBe("AnalysisOutputError");
    },
  );
  it.each([
    { ...file, sha256: "b".repeat(64) },
    { ...file, bytes: file.bytes + 1 },
  ])(
    "rejects a published source copy with mismatched metadata",
    async (copy) => {
      const returned = result();
      returned.source.published_copy = copy;
      const service = new JavaScriptDeobfuscationService({
        deobfuscate: async () =>
          ok(
            createAnalysisExecution(returned, provider, {
              subject: {
                path: file.path,
                sha256: file.sha256,
                format: "javascript",
              },
            }),
          ),
      });
      const response = await service.deobfuscate({
        path: file.path,
        output_directory: "/tmp/out",
      });
      if (response.ok) throw new Error("expected published source mismatch");
      expect(response.error._tag).toBe("AnalysisOutputError");
    },
  );
  it("preserves provider failures", async () => {
    const failure = new AnalysisCapabilityUnavailableError(
      "js-redox",
      "deobfuscate_javascript_source",
      "fixture unavailable",
    );
    const service = new JavaScriptDeobfuscationService({
      deobfuscate: async () => err(failure),
    });
    expect(
      await service.deobfuscate({
        path: file.path,
        output_directory: "/tmp/out",
      }),
    ).toEqual(err(failure));
  });

  it("accepts a schema-valid result bound to JavaScript Evidence", async () => {
    const service = new JavaScriptDeobfuscationService({
      deobfuscate: async () =>
        ok(
          createAnalysisExecution(result(), provider, {
            subject: {
              path: file.path,
              sha256: file.sha256,
              format: "javascript",
            },
          }),
        ),
    });
    const response = await service.deobfuscate({
      path: file.path,
      output_directory: "/tmp/out",
    });
    if (!response.ok) throw new Error("expected valid deobfuscation Evidence");
    if (response.value.subject === null)
      throw new Error("expected JavaScript Evidence subject");
    expect(response.value.subject.format).toBe("javascript");
  });

  it.skipIf(process.platform === "win32")(
    "canonicalizes a symlinked output parent before validating returned artifacts",
    async () => {
      const root = await createTestTempDirectory("rea-js-service-symlink-");
      const canonicalParent = join(root, "canonical");
      const aliasParent = join(root, "alias");
      await mkdir(canonicalParent, { recursive: true });
      await symlink(canonicalParent, aliasParent);
      const requestedOutput = join(aliasParent, "out");
      const canonicalOutput = join(canonicalParent, "out");
      const returned = result(canonicalOutput);
      const service = new JavaScriptDeobfuscationService({
        deobfuscate: async () =>
          ok(
            createAnalysisExecution(returned, provider, {
              subject: {
                path: file.path,
                sha256: file.sha256,
                format: "javascript",
              },
            }),
          ),
      });
      const response = await service.deobfuscate({
        path: file.path,
        output_directory: requestedOutput,
      });
      if (!response.ok) throw response.error;
      expect(response.value.normalized_result).toMatchObject({
        output: { path: join(canonicalOutput, "deobfuscated/source.js") },
      });
    },
  );

  it("rejects artifacts outside the canonical requested output tree", async () => {
    const returned = result();
    returned.output = { ...returned.output, path: "/tmp/elsewhere/source.js" };
    const service = new JavaScriptDeobfuscationService({
      deobfuscate: async () =>
        ok(
          createAnalysisExecution(returned, provider, {
            subject: {
              path: file.path,
              sha256: file.sha256,
              format: "javascript",
            },
          }),
        ),
    });
    const response = await service.deobfuscate({
      path: file.path,
      output_directory: "/tmp/out",
    });
    if (response.ok) throw new Error("expected output-tree binding rejection");
    expect(response.error._tag).toBe("AnalysisOutputError");
  });

  it("carries normalized and execution limitations into Evidence", async () => {
    const returned = result();
    returned.limitations = ["normalized caveat"];
    const service = new JavaScriptDeobfuscationService({
      deobfuscate: async () =>
        ok(
          createAnalysisExecution(returned, provider, {
            subject: {
              path: file.path,
              sha256: file.sha256,
              format: "javascript",
            },
            limitations: ["execution cleanup caveat"],
          }),
        ),
    });
    const response = await service.deobfuscate({
      path: file.path,
      output_directory: "/tmp/out",
    });
    if (!response.ok) throw response.error;
    expect(response.value.limitations).toEqual([
      "normalized caveat",
      "execution cleanup caveat",
    ]);
  });

  it.each([
    "invalid-result",
    "missing-subject",
    "subject-mismatch",
    "subject-format-mismatch",
    "proof-output-mismatch",
  ])("rejects %s returned across the provider boundary", async (mode) => {
    const service = new JavaScriptDeobfuscationService({
      deobfuscate: async () =>
        ok(
          createAnalysisExecution(
            mode === "invalid-result"
              ? {}
              : mode === "proof-output-mismatch"
                ? {
                    ...result(),
                    proof: {
                      ...result().proof,
                      output_sha256: "b".repeat(64),
                    },
                  }
                : result(),
            provider,
            mode === "missing-subject"
              ? {}
              : {
                  subject: {
                    path: mode === "subject-mismatch" ? "/wrong.js" : file.path,
                    sha256: file.sha256,
                    format:
                      mode === "subject-format-mismatch"
                        ? ("pe" as const)
                        : ("javascript" as const),
                  },
                },
          ),
        ),
    });
    const response = await service.deobfuscate({
      path: file.path,
      output_directory: "/tmp/out",
    });
    if (response.ok) throw new Error("expected invalid provider output");
    expect(response.error._tag).toBe("AnalysisOutputError");
  });

  it.each(["path", "output_directory"])(
    "rejects relative %s before invoking the provider",
    async (field) => {
      let invoked = false;
      const service = new JavaScriptDeobfuscationService({
        deobfuscate: async () => {
          invoked = true;
          return ok(createAnalysisExecution(result(), provider));
        },
      });
      const response = await service.deobfuscate({
        path: file.path,
        output_directory: "/tmp/out",
        [field]: "relative.js",
      });
      expect(invoked).toBe(false);
      if (response.ok) throw new Error("expected invalid path");
      expect(response.error._tag).toBe("AnalysisInputError");
    },
  );
});
