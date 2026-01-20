#!/usr/bin/env node

/**
 * AIPTX CLI - AI-Powered Penetration Testing Command Line Interface
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import Table from 'cli-table3';
import Conf from 'conf';
import { AIPTX, AIPTXError, type ScanRequest } from '@aiptx/sdk';

// =============================================================================
// Configuration Store
// =============================================================================

const config = new Conf({
  projectName: 'aiptx',
  schema: {
    apiUrl: { type: 'string', default: 'http://localhost:8000' },
    apiKey: { type: 'string', default: '' },
  },
});

// =============================================================================
// Helpers
// =============================================================================

function getClient(): AIPTX {
  return new AIPTX({
    baseUrl: config.get('apiUrl') as string,
    apiKey: config.get('apiKey') as string || undefined,
  });
}

function printBanner(): void {
  console.log(chalk.cyan(`
    ╔═══════════════════════════════════════════════════════════╗
    ║     █████╗ ██╗██████╗ ████████╗██╗  ██╗                   ║
    ║    ██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗██╔╝                   ║
    ║    ███████║██║██████╔╝   ██║    ╚███╔╝                    ║
    ║    ██╔══██║██║██╔═══╝    ██║    ██╔██╗                    ║
    ║    ██║  ██║██║██║        ██║   ██╔╝ ██╗                   ║
    ║    ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝                   ║
    ║                                                           ║
    ║          AI-Powered Penetration Testing Framework         ║
    ╚═══════════════════════════════════════════════════════════╝
  `));
}

function severityColor(severity: string): string {
  const colors: Record<string, typeof chalk.red> = {
    critical: chalk.red.bold,
    high: chalk.red,
    medium: chalk.yellow,
    low: chalk.blue,
    info: chalk.gray,
  };
  return (colors[severity] || chalk.white)(severity);
}

// =============================================================================
// Commands
// =============================================================================

const program = new Command();

program
  .name('aiptx')
  .description('AIPTX - AI-Powered Penetration Testing CLI')
  .version('2.0.6');

// -----------------------------------------------------------------------------
// Config Command
// -----------------------------------------------------------------------------

program
  .command('config')
  .description('Configure AIPTX CLI')
  .option('--api-url <url>', 'Set API server URL')
  .option('--api-key <key>', 'Set API key')
  .option('--show', 'Show current configuration')
  .action((options) => {
    if (options.show) {
      console.log(chalk.cyan('\nCurrent Configuration:'));
      console.log(`  API URL: ${config.get('apiUrl')}`);
      console.log(`  API Key: ${config.get('apiKey') ? '****' : '(not set)'}\n`);
      return;
    }

    if (options.apiUrl) {
      config.set('apiUrl', options.apiUrl);
      console.log(chalk.green(`✓ API URL set to: ${options.apiUrl}`));
    }

    if (options.apiKey) {
      config.set('apiKey', options.apiKey);
      console.log(chalk.green('✓ API Key configured'));
    }

    if (!options.apiUrl && !options.apiKey) {
      console.log('Use --api-url or --api-key to configure, or --show to view');
    }
  });

// -----------------------------------------------------------------------------
// Status Command
// -----------------------------------------------------------------------------

program
  .command('status')
  .description('Check AIPTX server status')
  .action(async () => {
    const spinner = ora('Checking server status...').start();
    const client = getClient();

    try {
      const health = await client.health();
      spinner.succeed('Server is healthy');

      console.log(chalk.cyan('\nServer Information:'));
      console.log(`  Version: ${health.version}`);
      console.log(`  Uptime: ${Math.floor(health.uptime / 60)} minutes`);

      console.log(chalk.cyan('\nComponents:'));
      console.log(`  Database: ${health.components.database ? chalk.green('✓') : chalk.red('✗')}`);
      console.log(`  LLM: ${health.components.llm ? chalk.green('✓') : chalk.red('✗')}`);

      if (health.components.scanners) {
        console.log(chalk.cyan('\nScanners:'));
        for (const [name, status] of Object.entries(health.components.scanners)) {
          console.log(`  ${name}: ${status ? chalk.green('✓') : chalk.red('✗')}`);
        }
      }
    } catch (error) {
      spinner.fail('Failed to connect to server');
      if (error instanceof AIPTXError) {
        console.error(chalk.red(`Error: ${error.message}`));
      }
      process.exit(1);
    }
  });

// -----------------------------------------------------------------------------
// Scan Command
// -----------------------------------------------------------------------------

program
  .command('scan <target>')
  .description('Start a security scan')
  .option('-m, --mode <mode>', 'Scan mode: quick, standard, full', 'standard')
  .option('--ai', 'Enable AI-guided scanning')
  .option('--exploit', 'Enable exploitation testing')
  .option('--json', 'Output results as JSON')
  .action(async (target, options) => {
    printBanner();
    const client = getClient();

    const request: ScanRequest = {
      target,
      mode: options.mode,
      ai: options.ai || false,
      exploit: options.exploit || false,
    };

    console.log(chalk.cyan(`\nStarting ${options.mode} scan on ${chalk.bold(target)}`));
    if (options.ai) console.log(chalk.yellow('  AI-guided mode enabled'));
    if (options.exploit) console.log(chalk.red('  Exploitation testing enabled'));
    console.log();

    const spinner = ora('Initializing scan...').start();

    try {
      const scan = await client.startScan(request);
      spinner.succeed(`Scan started (ID: ${scan.id})`);

      // Stream progress
      let lastPhase = '';
      const findings: unknown[] = [];

      const cleanup = client.streamScan(scan.id, {
        onProgress: (progress, phase) => {
          if (phase !== lastPhase) {
            console.log(chalk.cyan(`\n[${phase.toUpperCase()}]`));
            lastPhase = phase;
          }
          process.stdout.write(`\r  Progress: ${progress}%`);
        },
        onFinding: (finding) => {
          findings.push(finding);
          console.log(`\n  ${chalk.green('+')} ${finding.type}: ${finding.value} ${severityColor(finding.severity)}`);
        },
        onComplete: (status) => {
          console.log(chalk.green(`\n\n✓ Scan completed!`));
          console.log(`  Total findings: ${status.findings_count}`);

          if (options.json) {
            console.log(JSON.stringify(findings, null, 2));
          }
        },
        onError: (error) => {
          console.error(chalk.red(`\nError: ${error.message}`));
          cleanup();
          process.exit(1);
        },
      });

      // Handle Ctrl+C
      process.on('SIGINT', () => {
        cleanup();
        console.log(chalk.yellow('\nScan interrupted'));
        process.exit(0);
      });
    } catch (error) {
      spinner.fail('Failed to start scan');
      if (error instanceof AIPTXError) {
        console.error(chalk.red(`Error: ${error.message}`));
      }
      process.exit(1);
    }
  });

// -----------------------------------------------------------------------------
// Projects Command
// -----------------------------------------------------------------------------

program
  .command('projects')
  .description('List all projects')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    const spinner = ora('Loading projects...').start();
    const client = getClient();

    try {
      const projects = await client.listProjects();
      spinner.stop();

      if (options.json) {
        console.log(JSON.stringify(projects, null, 2));
        return;
      }

      if (projects.length === 0) {
        console.log(chalk.yellow('No projects found'));
        return;
      }

      const table = new Table({
        head: ['ID', 'Name', 'Target', 'Created'],
        style: { head: ['cyan'] },
      });

      for (const project of projects) {
        table.push([
          project.id,
          project.name,
          project.target,
          new Date(project.created_at).toLocaleDateString(),
        ]);
      }

      console.log(table.toString());
    } catch (error) {
      spinner.fail('Failed to load projects');
      if (error instanceof AIPTXError) {
        console.error(chalk.red(`Error: ${error.message}`));
      }
      process.exit(1);
    }
  });

// -----------------------------------------------------------------------------
// Findings Command
// -----------------------------------------------------------------------------

program
  .command('findings')
  .description('List findings')
  .option('-p, --project <id>', 'Filter by project ID')
  .option('-s, --severity <level>', 'Filter by severity')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    const spinner = ora('Loading findings...').start();
    const client = getClient();

    try {
      const findings = await client.listFindings({
        projectId: options.project ? parseInt(options.project) : undefined,
        severity: options.severity,
      });
      spinner.stop();

      if (options.json) {
        console.log(JSON.stringify(findings, null, 2));
        return;
      }

      if (findings.length === 0) {
        console.log(chalk.yellow('No findings found'));
        return;
      }

      const table = new Table({
        head: ['ID', 'Type', 'Value', 'Severity', 'Tool'],
        style: { head: ['cyan'] },
      });

      for (const finding of findings) {
        table.push([
          finding.id,
          finding.type,
          finding.value.substring(0, 40),
          severityColor(finding.severity),
          finding.tool,
        ]);
      }

      console.log(table.toString());
      console.log(chalk.gray(`\nTotal: ${findings.length} findings`));
    } catch (error) {
      spinner.fail('Failed to load findings');
      if (error instanceof AIPTXError) {
        console.error(chalk.red(`Error: ${error.message}`));
      }
      process.exit(1);
    }
  });

// -----------------------------------------------------------------------------
// Tools Command
// -----------------------------------------------------------------------------

program
  .command('tools')
  .description('List available security tools')
  .action(async () => {
    const spinner = ora('Loading tools...').start();
    const client = getClient();

    try {
      const tools = await client.listTools();
      spinner.stop();

      const table = new Table({
        head: ['Name', 'Phase', 'Available', 'Description'],
        style: { head: ['cyan'] },
        colWidths: [15, 10, 10, 50],
      });

      for (const tool of tools) {
        table.push([
          tool.name,
          tool.phase,
          tool.available ? chalk.green('✓') : chalk.red('✗'),
          tool.description.substring(0, 45),
        ]);
      }

      console.log(table.toString());
    } catch (error) {
      spinner.fail('Failed to load tools');
      if (error instanceof AIPTXError) {
        console.error(chalk.red(`Error: ${error.message}`));
      }
      process.exit(1);
    }
  });

// =============================================================================
// Run CLI
// =============================================================================

program.parse();
