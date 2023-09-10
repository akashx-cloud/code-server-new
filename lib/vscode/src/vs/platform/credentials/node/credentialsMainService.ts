/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { InMemoryCredentialsProvider } from 'vs/platform/credentials/common/credentials';
import { ILogService } from 'vs/platform/log/common/log';
import { IServerEnvironmentService } from 'vs/server/node/serverEnvironmentService';
import { IProductService } from 'vs/platform/product/common/productService';
import { BaseCredentialsMainService, KeytarModule } from 'vs/platform/credentials/common/credentialsMainService';
import { generateUuid } from 'vs/base/common/uuid';
import { equals as arrayEquals } from 'vs/base/common/arrays';

interface IToken {
	accessToken: string
	account?: { label: string }
	id: string
	scopes: string[]
}

export class CredentialsWebMainService extends BaseCredentialsMainService {
	// Since we fallback to the in-memory credentials provider, we do not need to surface any Keytar load errors
	// to the user.
	protected surfaceKeytarLoadError?: (err: any) => void;

	constructor(
		@ILogService logService: ILogService,
		@IServerEnvironmentService private readonly environmentMainService: IServerEnvironmentService,
		@IProductService private readonly productService: IProductService,
	) {
		super(logService);
		if (this.environmentMainService.args["github-auth"]) {
			this.storeGitHubToken(this.environmentMainService.args["github-auth"]).catch((error) => {
				this.logService.error('Failed to store provided GitHub token', error)
			})
		}
	}

	// If the credentials service is running on the server, we add a suffix -server to differentiate from the location that the
	// client would store the credentials.
	public override async getSecretStoragePrefix() { return Promise.resolve(`${this.productService.urlProtocol}-server`); }

	protected async withKeytar(): Promise<KeytarModule> {
		if (this._keytarCache) {
			return this._keytarCache;
		}

		if (this.environmentMainService.disableKeytar) {
			this.logService.info('Keytar is disabled. Using in-memory credential store instead.');
			this._keytarCache = new InMemoryCredentialsProvider();
			return this._keytarCache;
		}

		try {
			this._keytarCache = await import('keytar');
			// Try using keytar to see if it throws or not.
			await this._keytarCache.findCredentials('test-keytar-loads');
		} catch (e) {
			this.logService.warn(
				`Using the in-memory credential store as the operating system's credential store could not be accessed. Please see https://aka.ms/vscode-server-keyring on how to set this up. Details: ${e.message ?? e}`);
			this._keytarCache = new InMemoryCredentialsProvider();
		}
		return this._keytarCache;
	}

	private async storeGitHubToken(githubToken: string): Promise<void> {
		const extensionId = 'vscode.github-authentication';
		const service = `${await this.getSecretStoragePrefix()}${extensionId}`;
		const account = 'github.auth';
		const scopes = [['read:user', 'user:email', 'repo']]

		// Oddly the scopes need to match exactly so we cannot just have one token
		// with all the scopes, instead we have to duplicate the token for each
		// expected set of scopes.
		const tokens: IToken[] = scopes.map((scopes) => ({
			id: generateUuid(),
			scopes: scopes.sort(), // Sort for comparing later.
			accessToken: githubToken,
		}));

		const raw = await this.getPassword(service, account)

		let existing: {
			content: IToken[]
		} | undefined;

		if (raw) {
			try {
				const json = JSON.parse(raw);
				json.content = JSON.parse(json.content);
				existing = json;
			} catch (error) {
				this.logService.error('Failed to parse existing GitHub credentials', error)
			}
		}

		// Keep tokens for account and scope combinations we do not have in case
		// there is an extension that uses scopes we have not accounted for (in
		// these cases the user will need to manually authenticate the extension
		// through the UI) or the user has tokens for other accounts.
		if (existing?.content) {
			existing.content = existing.content.filter((existingToken) => {
				const scopes = existingToken.scopes.sort();
				return !(tokens.find((token) => {
					return arrayEquals(scopes, token.scopes)
						&& token.account?.label === existingToken.account?.label;
				}))
			})
		}

		return this.setPassword(service, account, JSON.stringify({
			extensionId,
			...(existing || {}),
			content: JSON.stringify([
				...tokens,
				...(existing?.content || []),
			])
		}));
	}
}
