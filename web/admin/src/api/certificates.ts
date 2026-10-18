import { FetcherMethod, fetcher } from "./api"

export interface CertificateRef {
    kind: string
    id: string
}

export interface CertificateRecord {
    ref: CertificateRef
    owner_id: number | string
    name: string
    source: "request" | "upload"
    status: "active" | "expired" | "revoked" | string
    serial_number: string
    subject: string
    issuer: string
    dns_names: string[]
    ip_addresses?: string[]
    not_before: string
    not_after: string
    revision: number
    created_at: string
    updated_at: string
}

export interface CertificateBundle {
    record: CertificateRecord
    certificate_pem: string
    private_key_pem?: string
}

export interface CertificateUpload {
    name: string
    certificate: File
    privateKey: File
}

export const listCertificates = async (): Promise<CertificateRecord[]> => {
    return (
        (await fetcher<CertificateRecord[]>(FetcherMethod.GET, "/api/v1/certificates", null)) ?? []
    )
}

export const getCertificate = async (id: string): Promise<CertificateRecord> => {
    return fetcher<CertificateRecord>(
        FetcherMethod.GET,
        `/api/v1/certificates/${encodeURIComponent(id)}`,
        null,
    )
}

export const createCertificate = async ({ name, certificate, privateKey }: CertificateUpload) => {
    const form = new FormData()
    form.set("name", name)
    form.set("certificate", certificate)
    form.set("private_key", privateKey)
    return fetcher<CertificateRecord>(FetcherMethod.POST, "/api/v1/certificates", form)
}

export const downloadCertificate = async (id: string, includePrivate = false) => {
    return fetcher<CertificateBundle>(
        FetcherMethod.GET,
        `/api/v1/certificates/${encodeURIComponent(id)}/download`,
        includePrivate ? { include_private: "true" } : undefined,
    )
}

export const deleteCertificate = async (id: string): Promise<void> => {
    return fetcher<void>(
        FetcherMethod.DELETE,
        `/api/v1/certificates/${encodeURIComponent(id)}`,
        null,
    )
}
