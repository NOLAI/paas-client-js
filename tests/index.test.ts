import {
  PseudonymService,
  PseudonymServiceConfig,
  TranscryptorConfig,
  EncryptionContexts,
} from "../dist/paas-client";
// @ts-ignore
import {
  BlindedGlobalSecretKey,
  EncryptedPseudonym,
  GlobalPublicKey,
} from "@nolai/libpep-wasm";
import { setupServer } from "msw/node";
import { http } from "msw";

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
);

describe("PaaS js client tests", () => {
  beforeAll(() => server.listen());
  afterAll(() => server.close());

  test("Create PEP client", async () => {
    const config: PseudonymServiceConfig = {
      blindedGlobalPrivateKey: BlindedGlobalSecretKey.fromHex(
        "dacec694506fa1c1ab562059174b022151acab4594723614811eaaa93a9c5908",
      ),
      globalPublicKey: GlobalPublicKey.fromHex(
        "3025b1584bc729154f33071f73bb9499509bb504f887496ba86cb57e88d5dc62",
      ),
      transcryptors: [
        new TranscryptorConfig("test_system_1", "http://localhost:8080"),
        new TranscryptorConfig("test_system_2", "http://localhost:8081"),
      ],
    };

    const authTokens = new Map<string, string>();
    authTokens.set("test_system_1", "test_token_1");
    authTokens.set("test_system_2", "test_token_2");

    const service = new PseudonymService(config, authTokens);
    await service.init();
    expect(service).toBeDefined();
  });

  test("Pseudonymize", async () => {
    const config: PseudonymServiceConfig = {
      blindedGlobalPrivateKey: BlindedGlobalSecretKey.fromHex(
        "dacec694506fa1c1ab562059174b022151acab4594723614811eaaa93a9c5908",
      ),
      globalPublicKey: GlobalPublicKey.fromHex(
        "3025b1584bc729154f33071f73bb9499509bb504f887496ba86cb57e88d5dc62",
      ),
      transcryptors: [
        new TranscryptorConfig("test_system_1", "http://localhost:8080"),
        new TranscryptorConfig("test_system_2", "http://localhost:8081"),
      ],
    };
    const authTokens = new Map([
      ["test_system_1", "test_token_1"],
      ["test_system_2", "test_token_2"],
    ]);

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

    const service = new PseudonymService(config, authTokens);
    const result = await service.pseudonymize(
      encryptedPseudonym,
      sessions,
      domainFrom,
      domainTo,
    );

    expect(result.asBase64()).toEqual(
      "gqmiHiFA8dMdNtbCgsJ-EEfT9fjTV91BrfcHKN57e2vaLR2_UJEVExd6o9tdZg7vKGQklYZwV3REOaOQedKtUA==",
    );

    const pseudonym = await service.decryptPseudonym(result);
    expect(pseudonym.asHex()).toEqual(
      "40280c88c76aa1ecdd567129d5ea7821a0b79b25bbe5eb2220eedc215feb450b",
    );
  }, 60000);
});
