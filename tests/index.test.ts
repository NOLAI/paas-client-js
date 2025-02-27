import {
  PseudonymService,
    PAASConfig,
  TranscryptorConfig,
  EncryptionContexts,
  SystemAuths,
  SystemId
} from "../dist/paas-client.js";
// @ts-ignore
import {
  BlindedGlobalSecretKey,
  EncryptedPseudonym,
  GlobalPublicKey,
} from "@nolai/libpep-wasm";
import { setupServer } from "msw/node";
import { http } from "msw";

const config: PAASConfig = {
    // eslint-disable-next-line camelcase
    blinded_global_secret_key:
      "dacec694506fa1c1ab562059174b022151acab4594723614811eaaa93a9c5908"
  ,
    // eslint-disable-next-line camelcase
  global_public_key:
      "3025b1584bc729154f33071f73bb9499509bb504f887496ba86cb57e88d5dc62"
  ,
  transcryptors: [
    new TranscryptorConfig("test_system_1", "http://localhost:8080"),
    new TranscryptorConfig("test_system_2", "http://localhost:8081"),
  ],
};

const authTokens = new Map<SystemId, string>([
  ["test_system_1", "test_token_1"],
  ["test_system_2", "test_token_2"],
]);

const auths = SystemAuths.fromTokens(authTokens);

const server = setupServer();
server.use(
  http.post("http://localhost:8080/sessions/start", async ({ request }) => {
    // Verify request headers
    const authHeader = request.headers.get("Authorization");
    expect(authHeader).toBe("Bearer test_token_1");

    return new Response(
      JSON.stringify({
        // eslint-disable-next-line camelcase
        session_id: "test_session_1",
        // eslint-disable-next-line camelcase
        key_share:
          "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a",
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      },
    );
  }),

  http.post("http://localhost:8081/sessions/start", async ({ request }) => {
    const authHeader = request.headers.get("Authorization");
    expect(authHeader).toBe("Bearer test_token_2");

    return new Response(
      JSON.stringify({
        // eslint-disable-next-line camelcase
        session_id: "test_session_2",
        // eslint-disable-next-line camelcase
        key_share:
          "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a",
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      },
    );
  }),

  http.post("http://localhost:8080/pseudonymize", async ({ request }) => {
    const authHeader = request.headers.get("Authorization");
    expect(authHeader).toBe("Bearer test_token_1");

    const body = await request.json();
    expect(body).toHaveProperty("encrypted_pseudonym");
    expect(body).toHaveProperty("domain_from", "domain1");
    expect(body).toHaveProperty("domain_to", "domain2");
    expect(body).toHaveProperty("session_from", "session_1");
    expect(body).toHaveProperty("session_to", "test_session_1");

    return new Response(
      JSON.stringify({
        // eslint-disable-next-line camelcase
        encrypted_pseudonym:
          "gqmiHiFA8dMdNtbCgsJ-EEfT9fjTV91BrfcHKN57e2vaLR2_UJEVExd6o9tdZg7vKGQklYZwV3REOaOQedKtUA==",
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      },
    );
  }),

  http.post("http://localhost:8081/pseudonymize", async ({ request }) => {
    const authHeader = request.headers.get("Authorization");
    expect(authHeader).toBe("Bearer test_token_2");

    const body = await request.json();
    expect(body).toHaveProperty("encrypted_pseudonym");
    expect(body).toHaveProperty("domain_from", "domain1");
    expect(body).toHaveProperty("domain_to", "domain2");
    expect(body).toHaveProperty("session_from", "session_2");
    expect(body).toHaveProperty("session_to", "test_session_2");

    return new Response(
      JSON.stringify({
        // eslint-disable-next-line camelcase
        encrypted_pseudonym:
          "gqmiHiFA8dMdNtbCgsJ-EEfT9fjTV91BrfcHKN57e2vaLR2_UJEVExd6o9tdZg7vKGQklYZwV3REOaOQedKtUA==",
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      },
    );
  }),

    http.get("http://localhost:8080/status", async ({ request }) => {
      const authHeader = request.headers.get("Authorization");
      expect(authHeader).toBe("Bearer test_token_1");

      return new Response(
        JSON.stringify({
          timestamp: "2021-10-14T15:00:00Z",
          // eslint-disable-next-line camelcase
          system_id: "test_system_1",
          // eslint-disable-next-line camelcase
          version_info: {
            // eslint-disable-next-line camelcase
            protocol_version: "0.1.0",
            // eslint-disable-next-line camelcase
            min_protocol_version: "0.1.0",
          },
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      );
    }),

    http.get("http://localhost:8081/status", async ({ request }) => {
      const authHeader = request.headers.get("Authorization");
      expect(authHeader).toBe("Bearer test_token_2");

        return new Response(
            JSON.stringify({
            timestamp: "2021-10-14T15:00:00Z",
            // eslint-disable-next-line camelcase
            system_id: "test_system_2",
            // eslint-disable-next-line camelcase
            version_info: {
              // eslint-disable-next-line camelcase
              protocol_version: "0.1.0",
              // eslint-disable-next-line camelcase
              min_protocol_version: "0.1.0",
            },
            }),
            {
            status: 200,
            headers: { "Content-Type": "application/json" },
            },
        );
    }),

    http.get("http://localhost:8080/config", async ({ request }) => {
        const authHeader = request.headers.get("Authorization");
        expect(authHeader).toBe("Bearer test_token_1");

        return new Response(
            JSON.stringify(config),
            {
            status: 200,
            headers: { "Content-Type": "application/json" },
            },
        );
    }),

    http.get("http://localhost:8081/config", async ({ request }) => {
      const authHeader = request.headers.get("Authorization");
      expect(authHeader).toBe("Bearer test_token_2");

      return new Response(
          JSON.stringify(config),
          {
            status: 200,
            headers: {"Content-Type": "application/json"},
          },
      );
    }),
);

describe("PaaS js client tests", () => {
  beforeAll(() => server.listen());
  afterAll(() => server.close());

  test("Create PEP client", async () => {
    const service = await PseudonymService.new(config, auths);
    await service.init();
    expect(service).toBeDefined();
  });

  test("Pseudonymize", async () => {
    const encryptedPseudonym = EncryptedPseudonym.fromBase64(
      "nr3FRadpFFGCFksYgrloo5J2V9j7JJWcUeiNBna66y78lwMia2-l8He4FfJPoAjuHCpH-8B0EThBr8DS3glHJw==",
    );
    const sessions = new EncryptionContexts(
      new Map([
        ["test_system_1", "session_1"],
        ["test_system_2", "session_2"],
      ]),
    );

    const domainFrom = "domain1";
    const domainTo = "domain2";

    const service = await PseudonymService.new(config, auths);
    const result = await service.pseudonymize(
      encryptedPseudonym,
      sessions,
      domainFrom,
      domainTo,
    );

    expect(result.asBase64()).toEqual(
      "gqmiHiFA8dMdNtbCgsJ-EEfT9fjTV91BrfcHKN57e2vaLR2_UJEVExd6o9tdZg7vKGQklYZwV3REOaOQedKtUA==",
    );

    const pseudonym = service.decrypt(result);
    expect(pseudonym.asHex()).toEqual(
      "40280c88c76aa1ecdd567129d5ea7821a0b79b25bbe5eb2220eedc215feb450b",
    );
  }, 60000);
});
