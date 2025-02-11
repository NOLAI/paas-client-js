export type SystemId = string;
export type EncryptionContext = string;
export type EncryptionContextsEncoded = string;

export class EncryptionContexts {
    private contexts: Map<SystemId, EncryptionContext>;

    constructor(contexts: Map<SystemId, EncryptionContext>) {
        this.contexts = contexts;
    }

    // Equivalent to the Rust get() method
    get(systemId: SystemId): EncryptionContext | undefined {
        return this.contexts.get(systemId);
    }

    // Equivalent to the Rust encode() method
    encode(): EncryptionContextsEncoded {
        const obj = Object.fromEntries(this.contexts);
        const jsonString = JSON.stringify(obj);
        return btoa(jsonString).replace(/\+/g, '-').replace(/\//g, '_');
    }

    // Equivalent to the Rust decode() method
    static decode(s: EncryptionContextsEncoded): EncryptionContexts | undefined {
        try {
            const base64 = s.replace(/-/g, '+').replace(/_/g, '/');
            const jsonString = atob(base64);
            const obj = JSON.parse(jsonString);
            const map = new Map<SystemId, EncryptionContext>(Object.entries(obj));
            return new EncryptionContexts(map);
        } catch {
            return undefined;
        }
    }

}