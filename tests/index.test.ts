import {
  PseudonymService,
  PAASConfig,
  TranscryptorConfig,
  EncryptionContexts,
  SystemAuths,
  SystemId,
} from "../dist/paas-client.js";
// @ts-ignore
import {
  AttributeGlobalPublicKey,
  BlindedAttributeGlobalSecretKey,
  BlindedGlobalKeys,
  BlindedPseudonymGlobalSecretKey,
  EncryptedPseudonym,
  GlobalPublicKeys,
  PseudonymGlobalPublicKey,
} from "@nolai/libpep-wasm";
import { setupServer } from "msw/node";
import { http } from "msw";

// Public global keys:
//   - Attributes: 94169b3b23113849006b385e568a916be16d91f5869ff9b01bd14ca41e79a848
//   - Pseudonyms: c49a19c142ee9c03624bdb4ee33e3072ab1fb9a10a5586c8c6001ebf7e72531c
// Blinded secret keys:
//   - Attributes: d92ff4a5a268cf38a0d1478e56007987dc339af1356afaf606fc55845abb2a03
//   - Pseudonyms: 6cc6d8c611e2ce3ab06c2328954726d50505419d92160bb21e128fd49397940d
// Blinding factors (keep secret):
//   - 1f861128928bb615582ddc4dfd22ac378ad82af99455fe81b7bd4751ede82d0c
//   - c0e4850c6e591cab3e68db39987dbde52870f2173631f4bb57b926601f083402

const config: PAASConfig = {
  // eslint-disable-next-line camelcase
  blinded_global_keys: {
    pseudonym:
      "6cc6d8c611e2ce3ab06c2328954726d50505419d92160bb21e128fd49397940d",
    attribute:
      "d92ff4a5a268cf38a0d1478e56007987dc339af1356afaf606fc55845abb2a03",
  },
  // eslint-disable-next-line camelcase
  global_public_keys: {
    pseudonym:
      "c49a19c142ee9c03624bdb4ee33e3072ab1fb9a10a5586c8c6001ebf7e72531c",
    attribute:
      "94169b3b23113849006b385e568a916be16d91f5869ff9b01bd14ca41e79a848",
  },
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
        session_key_shares: {
          pseudonym:
            "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a",
          attribute:
            "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a",
        },
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
        session_key_shares: {
          pseudonym:
            "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a",
          attribute:
            "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a",
        },
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      },
    );
  }),

  http.post(
    "http://localhost:8080/pseudonymize/pseudonym",
    async ({ request }) => {
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
    },
  ),

  http.post(
    "http://localhost:8081/pseudonymize/pseudonym",
    async ({ request }) => {
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
    },
  ),

  http.get("http://localhost:8080/status", async () => {
    return new Response(
      JSON.stringify({
        timestamp: "2021-10-14T15:00:00Z",
        // eslint-disable-next-line camelcase
        system_id: "test_system_1",
        // eslint-disable-next-line camelcase
        version_info: {
          // eslint-disable-next-line camelcase
          protocol_version: "0.10.0",
          // eslint-disable-next-line camelcase
          min_supported_version: "0.10.0",
        },
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      },
    );
  }),

  http.get("http://localhost:8081/status", async () => {
    return new Response(
      JSON.stringify({
        timestamp: "2021-10-14T15:00:00Z",
        // eslint-disable-next-line camelcase
        system_id: "test_system_2",
        // eslint-disable-next-line camelcase
        version_info: {
          // eslint-disable-next-line camelcase
          protocol_version: "0.10.0",
          // eslint-disable-next-line camelcase
          min_supported_version: "0.10.0",
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
      JSON.stringify({
        // eslint-disable-next-line camelcase
        blinded_global_keys: {
          pseudonym:
            "6cc6d8c611e2ce3ab06c2328954726d50505419d92160bb21e128fd49397940d",
          attribute:
            "d92ff4a5a268cf38a0d1478e56007987dc339af1356afaf606fc55845abb2a03",
        },
        // eslint-disable-next-line camelcase
        global_public_keys: {
          pseudonym:
            "c49a19c142ee9c03624bdb4ee33e3072ab1fb9a10a5586c8c6001ebf7e72531c",
          attribute:
            "94169b3b23113849006b385e568a916be16d91f5869ff9b01bd14ca41e79a848",
        },
        transcryptors: [
          // eslint-disable-next-line camelcase
          { system_id: "test_system_1", url: "http://localhost:8080" },
          // eslint-disable-next-line camelcase
          { system_id: "test_system_2", url: "http://localhost:8081" },
        ],
      }),
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
      JSON.stringify({
        // eslint-disable-next-line camelcase
        blinded_global_keys: {
          pseudonym:
            "6cc6d8c611e2ce3ab06c2328954726d50505419d92160bb21e128fd49397940d",
          attribute:
            "d92ff4a5a268cf38a0d1478e56007987dc339af1356afaf606fc55845abb2a03",
        },
        // eslint-disable-next-line camelcase
        global_public_keys: {
          pseudonym:
            "c49a19c142ee9c03624bdb4ee33e3072ab1fb9a10a5586c8c6001ebf7e72531c",
          attribute:
            "94169b3b23113849006b385e568a916be16d91f5869ff9b01bd14ca41e79a848",
        },
        transcryptors: [
          // eslint-disable-next-line camelcase
          { system_id: "test_system_1", url: "http://localhost:8080" },
          // eslint-disable-next-line camelcase
          { system_id: "test_system_2", url: "http://localhost:8081" },
        ],
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
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

    expect(result.toBase64()).toEqual(
      "gqmiHiFA8dMdNtbCgsJ-EEfT9fjTV91BrfcHKN57e2vaLR2_UJEVExd6o9tdZg7vKGQklYZwV3REOaOQedKtUA==",
    );

    const pseudonym = service.decrypt(result);
    expect(pseudonym.toHex()).toEqual(
      "a057b1e508716f696d42c7a27365d4336009ab52ab7ad15bb2672bccba1a673a",
    );
  }, 60000);
});
