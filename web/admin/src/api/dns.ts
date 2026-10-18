import { FetcherMethod, fetcher } from "./api"

export interface DNSZoneRef {
    kind: "dns_zone" | string
    id: string
}

export interface DNSZone {
    ref: DNSZoneRef
    owner_id: number
    provider: string
    remote: {
        id: string
        name: string
        access_mode?: string
        status?: string
    }
    credential?: { kind: string; id: string }
    revision: number
    state: string
    created_at?: string
    updated_at?: string
}

export type DNSRecordTTL = { mode: "explicit" | "automatic" | string; seconds: number }

export interface DNSRecord {
    id: string
    name: string
    type: string
    value: string
    ttl: DNSRecordTTL
    line?: string
    weight?: number
    proxied?: boolean
    disabled?: boolean
    comment?: string
    extensions?: Record<string, unknown>
}

export interface DNSRecordFilter {
    name?: string
    type?: string
    line?: string
}

export interface DNSPage<T> {
    items: T[]
    next_cursor?: string
}

export const listDNSZones = async (): Promise<DNSZone[]> => {
    return (await fetcher<DNSZone[]>(FetcherMethod.GET, "/api/v1/dns/zones", null)) ?? []
}

export const listDNSRecords = async (
    zoneId: string,
    filter: DNSRecordFilter = {},
    cursor?: string,
): Promise<DNSPage<DNSRecord>> => {
    const params: Record<string, string> = { limit: "100" }
    if (filter.name) params.name = filter.name
    if (filter.type) params.type = filter.type
    if (filter.line) params.line = filter.line
    if (cursor) params.cursor = cursor
    return (
        (await fetcher<DNSPage<DNSRecord>>(
            FetcherMethod.GET,
            `/api/v1/dns/zones/${encodeURIComponent(zoneId)}/records`,
            params,
        )) ?? { items: [], next_cursor: "" }
    )
}
