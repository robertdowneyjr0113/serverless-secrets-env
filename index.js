'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const BbPromise = require('bluebird');
const packageInfo = require('./package.json')

const algorithm = 'aes-256-cbc';

class ServerlessSecretsPlugin {
  constructor(serverless, options) {
    this.serverless = serverless;
    this.options = options;
    
    this.custom = this.serverless.service.custom[packageInfo.name] || {};
    this.config = this.serverless.config || {};
    this.stage = this.options.stage || this.serverless.service.provider.stage;
    
    this.secretsFilePathPrefix = this.custom.secretsFilePathPrefix || '';
    this.source = this.custom.source || `secrets.${this.stage}.yml`;
    this.entry = this.custom.entry || `${this.source.split('.yml')[0]}.encrypted`;

    const commandOptions = {
      stage: {
        usage: 'Stage of the file to encrypt',
        shortcut: 's',
        required: true,
      },
      password: {
        usage: 'Password to encrypt the file.',
        shortcut: 'p',
        required: true,
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
    return new BbPromise((resolve, reject) => {
      const servicePath = this.config.serviceDir;
      const secretsPath = path.resolve(servicePath, this.secretsFilePathPrefix, this.source);
      const encryptedCredentialsPath = path.resolve(servicePath, this.secretsFilePathPrefix, this.entry);
      
      this.options.password = crypto.pbkdf2Sync(this.options.password, 'default', 100000, 32, 'sha512');
      
      const iv = crypto.pbkdf2Sync(this.options.password, 'cipher-iv', 100000, 16, 'sha512');
      
      fs.createReadStream(secretsPath)
        .on('error', reject)
        .pipe(crypto.createCipheriv(algorithm, Buffer.from(this.options.password), iv))
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
    return new BbPromise((resolve, reject) => {
      const servicePath = this.config.serviceDir;
      const secretsPath = path.resolve(servicePath, this.secretsFilePathPrefix, this.source);
      const encryptedCredentialsPath = path.resolve(servicePath, this.secretsFilePathPrefix, this.entry);
      
      this.options.password = crypto.pbkdf2Sync(this.options.password, 'default', 100000, 32, 'sha512');
      const iv = crypto.pbkdf2Sync(this.options.password, 'cipher-iv', 100000, 16, 'sha512');

      fs.createReadStream(encryptedCredentialsPath)
        .on('error', reject)
        .pipe(crypto.createDecipheriv(algorithm, this.options.password, iv))
        .on('error', reject)
        .pipe(fs.createWriteStream(secretsPath))
        .on('error', reject)
        .on('close', () => {
          this.serverless.cli.log(`Successfully decrypted '${this.entry}' to '${this.source}'`);
          resolve();
        });
    });
  }

  checkFileExists() {
    return new BbPromise((resolve, reject) => {
      const servicePath = this.serverless.config.servicePath;
      const customPath = this.customPath;
      const credentialFileName = `secrets.${this.options.stage}.yml`;
      const secretsPath = path.join(servicePath, customPath, credentialFileName);
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
