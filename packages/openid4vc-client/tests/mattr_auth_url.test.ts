import { Agent, W3cCredentialsModule } from '@aries-framework/core'
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

    it('Should successfully generate an Authorization URL', async () => {
      const clientId = 'mobilewallet'
      const redirectUri = 'global.mattr.wallet://credentials/callback'
      const initiationUri = 'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fjohn-john-stzkbp.vii.au01.mattr.global%22%2C%22credentials%22%3A%5B%22969e5a08-ac5c-4304-8345-958236eed60d%22%5D%2C%20%22grants%22%3A%20%7B%22authorization_code%22%3A%20%7B%7D%7D%7D';

      const scope = ['ldp_vc:TestCourseCredential']
      const { authorizationUrl, codeVerifier } = await agent.modules.openId4VcClient.generateAuthorizationUrl({
        clientId,
        redirectUri,
        scope,
        uri: initiationUri,
      })

      // parse json-encoded URL into list of GET-parameters
      const decodedAuthUrl = decodeURIComponent(authorizationUrl);
      const jsonPosition = decodedAuthUrl.indexOf('{');
      const reqParams = JSON.parse(decodedAuthUrl.substring(jsonPosition));

      // replace the scope value 'openidldp_vc:TestCourseCredential' with 'ldp_vc:TestCourseCredential'
      reqParams.scope = reqParams.scope.replace('openid', '');
      const getParams = Object.entries(reqParams).map(kv => `${kv[0]}=${kv[1]}`).join('&');
      const newAuthUrl = `${decodedAuthUrl.substring(0, jsonPosition)}${getParams}`;
      console.log(`Auth URL: ${newAuthUrl}`);
      console.log(`Code verifier: ${codeVerifier}`);
    })
  })
})
