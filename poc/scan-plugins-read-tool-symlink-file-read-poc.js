#!/usr/bin/env node
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const DEFAULT_PLUGIN_REPO =
  "https://github.com/contohmarie/anthropic-scan-read-tool-poc-plugin-20260522230259";
const DEFAULT_NORMAL_SHA = "4986aca90f2ed7069de3f25be7078de71a62bb20";
const DEFAULT_SYMLINK_SHA = "5add51217791748d3b687914624560adb6e9dd86";

const actionPath =
  process.env.ACTION_PATH ||
  path.resolve(".github/actions/scan-plugins");
const validateLib =
  process.env.VALIDATE_LIB ||
  path.resolve(actionPath, "../validate-plugins/lib/common.sh");
const pluginRepo = process.env.POC_PLUGIN_REPO || DEFAULT_PLUGIN_REPO;
const normalSha = process.env.POC_NORMAL_PLUGIN_SHA || DEFAULT_NORMAL_SHA;
const symlinkSha = process.env.POC_SYMLINK_PLUGIN_SHA || DEFAULT_SYMLINK_SHA;

const normalMarker = "ANTHROPIC_POC_NORMAL_REPO_FILE";
const dummySecret = "ANTHROPIC_POC_SCAN_SECRET_12345";
const dummySecretPath = "/tmp/anthropic_poc_scan_secret";

if (!fs.existsSync(path.join(actionPath, "scripts", "scan.sh"))) {
  console.error("Could not find scan.sh. Run from claude-plugins-community or set ACTION_PATH.");
  process.exit(1);
}

fs.writeFileSync(dummySecretPath, `${dummySecret}\n`, { mode: 0o600 });

function writeEvent(res, event, data) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

function streamText(res, text, eventCounter) {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
  });
  const id = `msg_${++eventCounter.value}`;
  writeEvent(res, "message_start", {
    type: "message_start",
    message: {
      id,
      type: "message",
      role: "assistant",
      model: "claude-test",
      content: [],
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: 1, output_tokens: 0 },
    },
  });
  writeEvent(res, "content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "text", text: "" },
  });
  writeEvent(res, "content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: { type: "text_delta", text },
  });
  writeEvent(res, "content_block_stop", { type: "content_block_stop", index: 0 });
  writeEvent(res, "message_delta", {
    type: "message_delta",
    delta: { stop_reason: "end_turn", stop_sequence: null },
    usage: { output_tokens: 1 },
  });
  writeEvent(res, "message_stop", { type: "message_stop" });
  res.end();
}

function streamReadToolUse(res, eventCounter) {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
  });
  const id = `msg_${++eventCounter.value}`;
  writeEvent(res, "message_start", {
    type: "message_start",
    message: {
      id,
      type: "message",
      role: "assistant",
      model: "claude-test",
      content: [],
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: 1, output_tokens: 0 },
    },
  });
  writeEvent(res, "content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: {
      type: "tool_use",
      id: "toolu_read_skills_poc",
      name: "Read",
      input: {},
    },
  });
  writeEvent(res, "content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: {
      type: "input_json_delta",
      partial_json: JSON.stringify({ file_path: "skills/poc.md" }),
    },
  });
  writeEvent(res, "content_block_stop", { type: "content_block_stop", index: 0 });
  writeEvent(res, "message_delta", {
    type: "message_delta",
    delta: { stop_reason: "tool_use", stop_sequence: null },
    usage: { output_tokens: 1 },
  });
  writeEvent(res, "message_stop", { type: "message_stop" });
  res.end();
}

async function runScanCase({ label, pluginSha, expectedMarker, echoMarker }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `scan-action-read-${label}-`));
  const binDir = path.join(root, "bin");
  const marketplace = path.join(root, "marketplace.json");
  const outputFile = path.join(root, "github-output.txt");
  const summaryFile = path.join(root, "summary.md");
  const logFile = path.join(root, "scan.log");
  const apiRequestsFile = path.join(root, "api-requests.json");

  fs.mkdirSync(binDir, { recursive: true });
  // macOS does not ship GNU timeout. GitHub-hosted Linux runners do. This shim
  // keeps the local PoC portable while preserving the scan.sh call structure.
  fs.writeFileSync(
    path.join(binDir, "timeout"),
    "#!/usr/bin/env bash\nif [[ $1 =~ ^[0-9]+$ ]]; then shift; fi\nexec \"$@\"\n",
    { mode: 0o755 },
  );
  fs.writeFileSync(
    marketplace,
    JSON.stringify(
      {
        plugins: [
          {
            name: "scan-read-tool-poc",
            source: { url: pluginRepo, sha: pluginSha },
          },
        ],
      },
      null,
      2,
    ) + "\n",
  );

  let apiRequests = [];
  let sentReadToolUse = false;
  const eventCounter = { value: 0 };

  const fakeApi = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      apiRequests.push({ method: req.method, url: req.url, body });

      if (req.method === "HEAD") {
        res.statusCode = 200;
        res.end();
        return;
      }

      let parsed = {};
      try {
        parsed = JSON.parse(body);
      } catch {
        parsed = {};
      }

      const toolNames = (parsed.tools || []).map((tool) => tool.name);
      if (!sentReadToolUse && toolNames.includes("Read")) {
        sentReadToolUse = true;
        streamReadToolUse(res, eventCounter);
        return;
      }

      const verdict = JSON.stringify({
        passes: false,
        summary: `controlled echo marker: ${echoMarker}`,
        violations: `controlled echo marker: ${echoMarker}`,
        may_make_external_network_calls: false,
        may_download_additional_software: false,
      });
      streamText(res, verdict, eventCounter);
    });
  });

  return new Promise((resolve, reject) => {
    fakeApi.listen(0, "127.0.0.1", () => {
      const port = fakeApi.address().port;
      const env = {
        ...process.env,
        PATH: `${binDir}:${process.env.PATH}`,
        ACTION_PATH: actionPath,
        VALIDATE_LIB: validateLib,
        ANTHROPIC_API_KEY: "sk-ant-api03-DUMMY-TEST-ONLY",
        ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}`,
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        NO_PROXY: "127.0.0.1,localhost",
        MARKETPLACE_PATH: marketplace,
        BASE_REF: "0000000000000000000000000000000000000000",
        ALLOWED_HOSTS: "github.com",
        SCAN_TIMEOUT_SECS: "30",
        SCAN_ALL_EXTERNAL: "true",
        FAIL_ON_FINDINGS: "true",
        GITHUB_OUTPUT: outputFile,
        GITHUB_STEP_SUMMARY: summaryFile,
      };

      const child = spawn("bash", [path.join(actionPath, "scripts", "scan.sh")], {
        cwd: root,
        env,
        stdio: ["ignore", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => (stdout += chunk));
      child.stderr.on("data", (chunk) => (stderr += chunk));

      const killer = setTimeout(() => child.kill("SIGTERM"), 45_000);
      child.on("error", reject);
      child.on("close", (status) => {
        clearTimeout(killer);
        fakeApi.close();

        const summary = fs.existsSync(summaryFile)
          ? fs.readFileSync(summaryFile, "utf8")
          : "";
        const combinedLog = `${stdout}\n${stderr}\n${summary}`;
        const requestBody = apiRequests.map((request) => request.body).join("\n---REQUEST---\n");

        fs.writeFileSync(logFile, combinedLog);
        fs.writeFileSync(apiRequestsFile, JSON.stringify(apiRequests, null, 2));

        resolve({
          label,
          root,
          status,
          logFile,
          apiRequestsFile,
          publicPluginRepoCloned:
            combinedLog.includes("Scan: scan-read-tool-poc") &&
            !combinedLog.includes("clone/fetch/checkout failed"),
          readToolRequestedRepoSymlinkOrFile: sentReadToolUse,
          expectedMarkerInToolResult: requestBody.includes(expectedMarker),
          dummySecretInToolResult: requestBody.includes(dummySecret),
          echoMarkerReachedLogsOrSummary: combinedLog.includes(echoMarker),
        });
      });
    });
  });
}

(async () => {
  const normal = await runScanCase({
    label: "normal",
    pluginSha: normalSha,
    expectedMarker: normalMarker,
    echoMarker: normalMarker,
  });
  const symlink = await runScanCase({
    label: "symlink",
    pluginSha: symlinkSha,
    expectedMarker: dummySecret,
    echoMarker: dummySecret,
  });

  console.log(`normal_poc_root=${normal.root}`);
  console.log(`symlink_poc_root=${symlink.root}`);
  console.log(`normal_public_plugin_repo_cloned=${normal.publicPluginRepoCloned}`);
  console.log(`symlink_public_plugin_repo_cloned=${symlink.publicPluginRepoCloned}`);
  console.log("normal_plugin_file=skills/poc.md regular file");
  console.log(`symlink_plugin_file=skills/poc.md -> ${dummySecretPath}`);
  console.log(`normal_repo_file_read_inside_clone=${normal.expectedMarkerInToolResult}`);
  console.log(`normal_repo_file_did_not_include_dummy_secret=${!normal.dummySecretInToolResult}`);
  console.log(`symlink_target_outside_clone_read=${symlink.dummySecretInToolResult}`);
  console.log(
    `controlled_downstream_echo_to_logs_or_summary=${symlink.echoMarkerReachedLogsOrSummary}`,
  );
  console.log(`normal_scan_log=${normal.logFile}`);
  console.log(`symlink_scan_log=${symlink.logFile}`);
  console.log(`normal_api_requests=${normal.apiRequestsFile}`);
  console.log(`symlink_api_requests=${symlink.apiRequestsFile}`);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
