'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const BbPromise = require('bluebird');
const packageInfo = require('./package.json');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl._writeToOutput = function _writeToOutput(stringToWrite) {
  if (rl.stdoutMuted)
    rl.output.write('\x1B[2K\x1B[200D'+rl.query+'*'.repeat(rl.line.length));
  else
    rl.output.write(stringToWrite);
};

const algorithm = 'aes-256-cbc';

class ServerlessSecretsPlugin {
  constructor(serverless, options) {
    this.serverless = serverless;
    this.options = options;
    
    this.custom = this.serverless.service.custom[packageInfo.name] || {};
    this.config = this.serverless.config || {};
    this.stage = this.options.stage || this.serverless.service.provider.stage;
    
    this.servicePath = this.config.serviceDir;
    const secretsFilePathPrefix = this.custom.secretsFilePathPrefix || '';

    this.source = this.custom.source || `secrets.${this.stage}.yml`;
    this.entry = this.custom.entry || `${this.source.split('.yml')[0]}.encrypted`;

    this.sourceFile = path.basename(this.source);
    this.entryFile = path.basename(this.entry);

    this.sourceFolderPath = path.resolve(this.servicePath, secretsFilePathPrefix, this.source.split(this.sourceFile)[0]);
    this.entryFolderPath = path.resolve(this.servicePath, secretsFilePathPrefix, this.entry.split(this.entryFile)[0]);

    if (fs.existsSync(this.sourceFolderPath) || fs.existsSync(this.entryFolderPath)) {
      fs.mkdirSync(this.sourceFolderPath, {
        recursive: true,
      });
      fs.mkdirSync(this.entryFolderPath, {
        recursive: true,
      });
    }

    const commandOptions = {
      stage: {
        usage: 'Stage of the file to encrypt',
        shortcut: 's',
        required: false,
      },
      password: {
        usage: 'Password to encrypt the file.',
        shortcut: 'p',
        required: false,
      },
    };

    this.commands = {
      encrypt: {
        usage: 'Encrypt a secrets file for a specific stage.',
        lifecycleEvents: [
          'encrypt',
        ],
        options: commandOptions,
      },
      decrypt: {
        usage: 'Decrypt a secrets file for a specific stage.',
        lifecycleEvents: [
          'decrypt',
        ],
        options: commandOptions,
      },
    };

    this.hooks = {
      'encrypt:encrypt': this.encrypt.bind(this),
      'decrypt:decrypt': this.decrypt.bind(this),
      'package:cleanup': this.checkFileExists.bind(this),
    };
  }

  encrypt() {
    return new BbPromise(async (resolve, reject) => {
      const secretsPath = path.resolve(this.sourceFolderPath, this.sourceFile);
      const encryptedCredentialsPath = path.resolve(this.entryFolderPath, this.entryFile);

      const password = this.options.password || await this.readPassword();

      const hashpassword = crypto.pbkdf2Sync(password, 'default', 100000, 32, 'sha512');
      const iv = crypto.pbkdf2Sync(password, 'cipher-iv', 100000, 16, 'sha512');

      fs.createReadStream(secretsPath)
        .on('error', reject)
        .pipe(crypto.createCipheriv(algorithm, Buffer.from(hashpassword), iv))
        .on('error', reject)
        .pipe(fs.createWriteStream(encryptedCredentialsPath))
        .on('error', reject)
        .on('close', () => {
          this.serverless.cli.log(`Successfully encrypted '${this.source}' to '${this.entry}'`);
          resolve();
        });
    });
  }

  decrypt() {
    return new BbPromise(async (resolve, reject) => {
      const secretsPath = path.resolve(this.sourceFolderPath, this.sourceFile);
      const encryptedCredentialsPath = path.resolve(this.entryFolderPath, this.entryFile);

      const password = this.options.password || await this.readPassword();
      
      const hashpassword = crypto.pbkdf2Sync(password, 'default', 100000, 32, 'sha512');
      const iv = crypto.pbkdf2Sync(password, 'cipher-iv', 100000, 16, 'sha512');

      fs.createReadStream(encryptedCredentialsPath)
        .on('error', reject)
        .pipe(crypto.createDecipheriv(algorithm, hashpassword, iv))
        .on('error', reject)
        .pipe(fs.createWriteStream(secretsPath))
        .on('error', reject)
        .on('close', () => {
          this.serverless.cli.log(`Successfully decrypted '${this.entry}' to '${this.source}'`);
          resolve();
        });
    });
  }

  readPassword() {
    return new BbPromise(function (resolve) {
      rl.stdoutMuted = true;

      rl.query = 'Enter your password: ';
      rl.question(rl.query, function (password) {
        rl.history = rl.history.slice(1);
        rl.close();
        resolve(password);
      });
    });
  }

  checkFileExists() {
    return new BbPromise((resolve, reject) => {
      const secretsPath = path.resolve(this.sourceFolderPath, this.sourceFile);

      fs.access(secretsPath, fs.F_OK, (err) => {
        if (err) {
          reject(`Couldn't find the secrets file for this stage: ${credentialFileName}`);
        } else {
          resolve();
        }
      });
    });
  }
}

module.exports = ServerlessSecretsPlugin;
