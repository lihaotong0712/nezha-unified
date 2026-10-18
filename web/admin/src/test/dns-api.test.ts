import { listDNSRecords, listDNSZones } from "@/api/dns"
import { afterEach, expect, test, vi } from "vitest"

const originalFetch = globalThis.fetch

afterEach(() => {
    globalThis.fetch = originalFetch
    vi.restoreAllMocks()
})

test("listDNSZones uses the dashboard DNS endpoint and returns an empty list for no data", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ success: true, error: "", data: [] }), { status: 200 }),
    )
    globalThis.fetch = fetchMock
    await expect(listDNSZones()).resolves.toEqual([])
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/dns/zones", expect.objectContaining({ method: "GET" }))
})

test("listDNSRecords encodes zone IDs and exact filters", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ success: true, error: "", data: { items: [], next_cursor: "next" } }), { status: 200 }),
    )
    globalThis.fetch = fetchMock
    await expect(listDNSRecords("zone/a", { name: "_acme.example.com.", type: "TXT" }, "cursor-1")).resolves.toEqual({ items: [], next_cursor: "next" })
    expect(fetchMock.mock.calls[0][0]).toContain("/api/v1/dns/zones/zone%2Fa/records?")
    expect(fetchMock.mock.calls[0][0]).toContain("name=_acme.example.com.")
    expect(fetchMock.mock.calls[0][0]).toContain("type=TXT")
    expect(fetchMock.mock.calls[0][0]).toContain("cursor=cursor-1")
})
