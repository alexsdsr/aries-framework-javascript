import type { KeyDidCreateOptions } from '@aries-framework/core'

import {
  JwaSignatureAlgorithm,
  Agent,
  KeyType,
  TypedArrayEncoder,
  W3cCredentialsModule,
  DidKey,
} from '@aries-framework/core'

import { AskarModule } from '../../askar/src'
import { askarModuleConfig } from '../../askar/tests/helpers'
import { customDocumentLoader } from '../../core/src/modules/vc/data-integrity/__tests__/documentLoader'
import { getAgentOptions } from '../../core/tests'
import { OpenId4VcClientModule } from '@aries-framework/openid4vc-client'

const modules = {
  openId4VcClient: new OpenId4VcClientModule(),
  w3cCredentials: new W3cCredentialsModule({
    documentLoader: customDocumentLoader,
  }),
  askar: new AskarModule(askarModuleConfig),
}

describe('OpenId4VcClient', () => {
  let agent: Agent<typeof modules>

  beforeEach(async () => {
    const agentOptions = getAgentOptions('OpenId4VcClient Agent', {}, modules)
    agent = new Agent(agentOptions)
    await agent.initialize()
  })

  afterEach(async () => {
    await agent.shutdown()
    await agent.wallet.delete()
  })

  describe('Authorization flow', () => {

    it('Should successfully issue of VC with Mattr', async () => {
      let authCode = process.env['AUTHCODE'];

      if (process.env['AUTHCODE'] === undefined 
          && process.env['CODEVERIF'] === undefined) {
        return;
      }

      expect(authCode).toBeDefined()

      if(authCode!.includes('code=')) {
        const codeStartPosition = authCode!.indexOf('code=') + 5
        let codeEndPosition = authCode!.indexOf('&', codeStartPosition)
        codeEndPosition = codeEndPosition !== -1 ? codeEndPosition : authCode!.length
        authCode = authCode!.substring(codeStartPosition, codeEndPosition)
      }

      const codeVerifier = process.env['CODEVERIF'] as string;
      const did = await agent.dids.create<KeyDidCreateOptions>({
        method: 'key',
        options: {
          keyType: KeyType.Ed25519,
        },
        secret: {
          privateKey: TypedArrayEncoder.fromString('96213c3d7fc8d4d6754c7a0fd969598e'),
        },
      })

      const didKey = DidKey.fromDid(did.didState.did as string)
      const kid = `${did.didState.did as string}#${didKey.key.fingerprint}`
      const verificationMethod = did.didState.didDocument?.dereferenceKey(kid, ['authentication'])
      if (!verificationMethod) throw new Error('No verification method found')

      const clientId = 'mobilewallet'
      const redirectUri = 'global.mattr.wallet://credentials/callback'
      const initiationUri = 'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fjohn-john-stzkbp.vii.au01.mattr.global%22%2C%22credentials%22%3A%5B%22969e5a08-ac5c-4304-8345-958236eed60d%22%5D%2C%20%22grants%22%3A%20%7B%22authorization_code%22%3A%20%7B%7D%7D%7D';

      const w3cCredentialRecords = await agent.modules.openId4VcClient.requestCredentialUsingAuthorizationCode({
        clientId: clientId,
        authorizationCode: authCode!,
        codeVerifier: codeVerifier,
        verifyCredentialStatus: false,
        proofOfPossessionVerificationMethodResolver: () => verificationMethod,
        allowedProofOfPossessionSignatureAlgorithms: [JwaSignatureAlgorithm.EdDSA],
        uri: initiationUri,
        redirectUri: redirectUri,
      })

      expect(w3cCredentialRecords).toHaveLength(1)
    })
  })

})
