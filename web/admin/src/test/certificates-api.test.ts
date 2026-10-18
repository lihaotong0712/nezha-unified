import { createCertificate, downloadCertificate, listCertificates } from "@/api/certificates"
import { afterEach, expect, test, vi } from "vitest"

afterEach(() => {
    vi.unstubAllGlobals()
})

test("lists safe certificate metadata through the common API envelope", async () => {
    const fetchMock = vi.fn(
        async () =>
            new Response(
                JSON.stringify({
                    success: true,
                    error: "",
                    data: [{ ref: { kind: "certificate", id: "cert-1" }, name: "example" }],
                }),
                { status: 200, headers: { "Content-Type": "application/json" } },
            ),
    )
    vi.stubGlobal("fetch", fetchMock)

    await expect(listCertificates()).resolves.toEqual([
        { ref: { kind: "certificate", id: "cert-1" }, name: "example" },
    ])
    expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/certificates",
        expect.objectContaining({ method: "GET" }),
    )
})

test("uploads certificate and private key as multipart form data", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        expect(init?.body).toBeInstanceOf(FormData)
        const form = init?.body as FormData
        expect(form.get("name")).toBe("example")
        expect(form.get("certificate")).toBeInstanceOf(File)
        expect(form.get("private_key")).toBeInstanceOf(File)
        expect((init?.headers as Record<string, string>)?.["Content-Type"]).toBeUndefined()
        return new Response(JSON.stringify({ success: true, error: "", data: {} }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        })
    })
    vi.stubGlobal("fetch", fetchMock)

    await createCertificate({
        name: "example",
        certificate: new File(["certificate"], "cert.pem", { type: "application/x-pem-file" }),
        privateKey: new File(["private key"], "key.pem", { type: "application/x-pem-file" }),
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)
})

test("private-key download is explicit and query encoded", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
        expect(String(input)).toBe(
            "http://localhost:3000/api/v1/certificates/cert%2F1/download?include_private=true",
        )
        return new Response(
            JSON.stringify({
                success: true,
                error: "",
                data: { record: {}, certificate_pem: "Y2VydA==", private_key_pem: "a2V5" },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
        )
    })
    vi.stubGlobal("fetch", fetchMock)

    await expect(downloadCertificate("cert/1", true)).resolves.toMatchObject({
        certificate_pem: "Y2VydA==",
        private_key_pem: "a2V5",
    })
})
