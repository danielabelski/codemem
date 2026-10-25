import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { arch, availableParallelism, cpus, platform, tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const target = "packages/core/src/coordinator-legacy-completion-owner-proof.test.ts";
const phases = ["SQLite", "D1"].flatMap((backend) =>
	[
		"full 500 recovered subjects with production-shaped writer IDs",
		"full 500 recovered subjects: success",
		"full 500 recovered subjects: late source revocation",
	].map((title, index) => ({
		name: `${backend.toLowerCase()}-isolated-${index + 1}`,
		expectedTests: 1,
		args: [target, "-t", `^${backend} ${title}$`, "--maxWorkers=1"],
	})),
);
phases.push({
	name: "parallel-controls",
	expectedTests: 173,
	args: [
		target,
		"packages/core/src/coordinator-auth-lifecycle-recognition.test.ts",
		"packages/core/src/coordinator-legacy-owner-resolution-commit-atomic.test.ts",
		"--maxWorkers=3",
	],
});

function isolatedEnvironment(base) {
	const env = { ...base };
	for (const name of Object.keys(env)) {
		if (name.startsWith("CODEMEM_") || /(?:^|_)(?:API_KEY|TOKEN|SECRET)$/u.test(name))
			delete env[name];
	}
	const home = mkdtempSync(join(tmpdir(), "codemem-runtime-diagnostic-"));
	return {
		...env,
		HOME: home,
		CODEMEM_DB: join(home, "mem.sqlite"),
		CODEMEM_KEYS_DIR: join(home, "keys"),
		CODEMEM_CONFIG: join(home, "config.json"),
		CODEMEM_EMBEDDING_DISABLED: "1",
		CODEMEM_METRICS: "false",
		XDG_CONFIG_HOME: join(home, "config"),
		XDG_DATA_HOME: join(home, "data"),
		XDG_CACHE_HOME: join(home, "cache"),
		CI: "true",
	};
}

function runtimeMetadata() {
	const require = createRequire(join(root, "packages/core/package.json"));
	const Database = require("better-sqlite3");
	const db = new Database(":memory:");
	try {
		return {
			node: process.version,
			platform: platform(),
			arch: arch(),
			availableParallelism: availableParallelism(),
			cpuCount: cpus().length,
			cpuModel: cpus()[0]?.model,
			betterSqlite: require("better-sqlite3/package.json").version,
			sqlite: db.prepare("SELECT sqlite_version() AS version").get(),
			compileOptions: db.pragma("compile_options"),
		};
	} finally {
		db.close();
	}
}

function runPhase(phase, { output, env }) {
	const report = join(output, `${phase.name}.vitest.json`);
	const command = [
		"exec",
		"vitest",
		"run",
		...phase.args,
		"--reporter=json",
		"--outputFile",
		report,
	];
	console.info(JSON.stringify({ phase: phase.name, status: "starting", command }));
	const started = performance.now();
	const result = spawnSync("pnpm", command, {
		cwd: root,
		env: isolatedEnvironment(env),
		encoding: "utf8",
		maxBuffer: 32 * 1024 * 1024,
	});
	writeFileSync(join(output, `${phase.name}.stdout.log`), result.stdout ?? "");
	writeFileSync(join(output, `${phase.name}.stderr.log`), result.stderr ?? "");
	process.stdout.write(result.stdout ?? "");
	process.stderr.write(result.stderr ?? "");
	let executedTests = null;
	try {
		const counts = JSON.parse(readFileSync(report, "utf8"));
		executedTests = counts.numPassedTests + counts.numFailedTests;
	} catch {
		// A missing/malformed report is a diagnostic failure, never a passing phase.
	}
	const summary = {
		phase: phase.name,
		exitCode: result.status,
		signal: result.signal,
		error: result.error?.message,
		executedTests,
		selectionValid: executedTests === phase.expectedTests,
		elapsedMs: Math.round(performance.now() - started),
	};
	console.info(JSON.stringify(summary));
	return summary;
}

if (process.argv.includes("--plan")) {
	console.info(JSON.stringify({ target, phases }, null, 2));
} else {
	const output = join(root, ".tmp/completion-runtime-diagnostic");
	mkdirSync(output, { recursive: true });
	const metadata = runtimeMetadata();
	console.info(JSON.stringify({ runtime: metadata }));
	writeFileSync(join(output, "runtime.json"), `${JSON.stringify(metadata, null, 2)}\n`);
	// These are measurements, not replacement gates. Preserve every failed exit
	// while allowing the remaining controls to produce comparable evidence.
	const results = phases.map((phase) => runPhase(phase, { output, env: process.env }));
	writeFileSync(join(output, "summary.json"), `${JSON.stringify(results, null, 2)}\n`);
	if (results.some((result) => result.exitCode !== 0 || !result.selectionValid))
		process.exitCode = 1;
}
