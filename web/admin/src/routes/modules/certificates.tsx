import {
    CertificateRecord,
    createCertificate,
    deleteCertificate,
    downloadCertificate,
    getCertificate,
    listCertificates,
} from "@/api/certificates"
import { Button } from "@/components/ui/button"
import {
    Dialog,
    DialogClose,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table"
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { Link, useNavigate, useParams } from "react-router-dom"
import { toast } from "sonner"
import useSWR from "swr"

import { ModuleErrorState } from "./error"

const formatDate = (value: string) => {
    const date = new Date(value)
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

const downloadText = (name: string, content: string, mime = "application/x-pem-file") => {
    const bytes = content.startsWith("-----BEGIN")
        ? new TextEncoder().encode(content)
        : Uint8Array.from(atob(content), (char) => char.charCodeAt(0))
    const url = URL.createObjectURL(new Blob([bytes], { type: mime }))
    const anchor = document.createElement("a")
    anchor.href = url
    anchor.download = name
    anchor.click()
    URL.revokeObjectURL(url)
}

export function CertificatesPage() {
    const { t } = useTranslation()
    const navigate = useNavigate()
    const { data, error, isLoading, mutate } = useSWR<CertificateRecord[]>(
        "/api/v1/certificates",
        listCertificates,
    )
    const [uploadOpen, setUploadOpen] = useState(false)

    useEffect(() => {
        if (error) toast(t("Error"), { description: error.message })
    }, [error, t])

    const remove = async (record: CertificateRecord) => {
        if (!window.confirm(t("Modules.pages.certificates.confirmDelete", { name: record.name }))) {
            return
        }
        try {
            await deleteCertificate(record.ref.id)
            toast(t("Modules.pages.certificates.deleted"))
            await mutate()
        } catch (err) {
            toast(t("Error"), { description: err instanceof Error ? err.message : String(err) })
        }
    }

    return (
        <>
            <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-2">
                    <h1 className="text-3xl font-bold tracking-tight">
                        {t("Modules.pages.certificates.title")}
                    </h1>
                    <p className="text-muted-foreground">
                        {t("Modules.pages.certificates.description")}
                    </p>
                </div>
                <Button onClick={() => setUploadOpen(true)}>
                    {t("Modules.pages.certificates.upload")}
                </Button>
            </div>
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead>{t("Name")}</TableHead>
                        <TableHead>{t("Modules.pages.certificates.domains")}</TableHead>
                        <TableHead>{t("Modules.pages.certificates.status")}</TableHead>
                        <TableHead>{t("Modules.pages.certificates.expires")}</TableHead>
                        <TableHead>{t("Actions")}</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {isLoading ? (
                        <TableRow>
                            <TableCell colSpan={5} className="h-24 text-center">
                                {t("Loading")}...
                            </TableCell>
                        </TableRow>
                    ) : !data?.length ? (
                        <TableRow>
                            <TableCell
                                colSpan={5}
                                className="h-24 text-center text-muted-foreground"
                            >
                                {t("Modules.pages.certificates.empty")}
                            </TableCell>
                        </TableRow>
                    ) : (
                        data.map((record) => (
                            <TableRow key={record.ref.id}>
                                <TableCell>
                                    <Link
                                        className="font-medium underline-offset-4 hover:underline"
                                        to={`/dashboard/certificates/${encodeURIComponent(record.ref.id)}`}
                                    >
                                        {record.name}
                                    </Link>
                                </TableCell>
                                <TableCell className="max-w-xs truncate">
                                    {[
                                        ...(record.dns_names ?? []),
                                        ...(record.ip_addresses ?? []),
                                    ].join(", ")}
                                </TableCell>
                                <TableCell>
                                    {t(`Modules.certificateStatus.${record.status}`, record.status)}
                                </TableCell>
                                <TableCell>{formatDate(record.not_after)}</TableCell>
                                <TableCell className="space-x-2 whitespace-nowrap">
                                    <Button
                                        size="sm"
                                        variant="outline"
                                        onClick={() =>
                                            navigate(
                                                `/dashboard/certificates/${encodeURIComponent(record.ref.id)}`,
                                            )
                                        }
                                    >
                                        {t("View")}
                                    </Button>
                                    <Button
                                        size="sm"
                                        variant="destructive"
                                        onClick={() => remove(record)}
                                    >
                                        {t("Delete")}
                                    </Button>
                                </TableCell>
                            </TableRow>
                        ))
                    )}
                </TableBody>
            </Table>
            <UploadCertificateDialog
                open={uploadOpen}
                onOpenChange={setUploadOpen}
                onCreated={async () => {
                    await mutate()
                    setUploadOpen(false)
                }}
            />
        </>
    )
}

function UploadCertificateDialog({
    open,
    onOpenChange,
    onCreated,
}: {
    open: boolean
    onOpenChange: (open: boolean) => void
    onCreated: () => Promise<void>
}) {
    const { t } = useTranslation()
    const [name, setName] = useState("")
    const [certificate, setCertificate] = useState<File>()
    const [privateKey, setPrivateKey] = useState<File>()
    const [submitting, setSubmitting] = useState(false)

    const submit = async () => {
        if (!name.trim() || !certificate || !privateKey) {
            toast(t("Error"), { description: t("Modules.pages.certificates.uploadRequired") })
            return
        }
        setSubmitting(true)
        try {
            await createCertificate({ name: name.trim(), certificate, privateKey })
            toast(t("Modules.pages.certificates.created"))
            setName("")
            setCertificate(undefined)
            setPrivateKey(undefined)
            await onCreated()
        } catch (err) {
            toast(t("Error"), { description: err instanceof Error ? err.message : String(err) })
        } finally {
            setSubmitting(false)
        }
    }

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>{t("Modules.pages.certificates.upload")}</DialogTitle>
                    <DialogDescription>
                        {t("Modules.pages.certificates.uploadDescription")}
                    </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                    <div className="space-y-2">
                        <Label htmlFor="certificate-name">{t("Name")}</Label>
                        <Input
                            id="certificate-name"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                        />
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="certificate-pem">
                            {t("Modules.pages.certificates.certificateFile")}
                        </Label>
                        <Input
                            id="certificate-pem"
                            type="file"
                            accept=".pem,.crt,.cer"
                            onChange={(e) => setCertificate(e.target.files?.[0])}
                        />
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="private-key-pem">
                            {t("Modules.pages.certificates.privateKeyFile")}
                        </Label>
                        <Input
                            id="private-key-pem"
                            type="file"
                            accept=".pem,.key"
                            onChange={(e) => setPrivateKey(e.target.files?.[0])}
                        />
                    </div>
                </div>
                <DialogFooter>
                    <DialogClose asChild>
                        <Button variant="outline">{t("Cancel")}</Button>
                    </DialogClose>
                    <Button onClick={submit} disabled={submitting}>
                        {submitting ? `${t("Loading")}...` : t("Create")}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    )
}

export function CertificateDetailPage() {
    const { t } = useTranslation()
    const { id = "" } = useParams()
    const navigate = useNavigate()
    const { data, error, isLoading } = useSWR<CertificateRecord>(
        id ? `/api/v1/certificates/${id}` : null,
        () => getCertificate(id),
    )
    useEffect(() => {
        if (error) toast(t("Error"), { description: error.message })
    }, [error, t])

    if (isLoading) return <p className="text-muted-foreground">{t("Loading")}...</p>
    if (!data) return <ModuleErrorState status={404} />

    const download = async (includePrivate: boolean) => {
        try {
            const bundle = await downloadCertificate(data.ref.id, includePrivate)
            downloadText(
                `${data.name}${includePrivate ? ".bundle.pem" : ".crt"}`,
                bundle.certificate_pem,
            )
            if (includePrivate && bundle.private_key_pem) {
                downloadText(`${data.name}.key`, bundle.private_key_pem)
            }
        } catch (err) {
            toast(t("Error"), { description: err instanceof Error ? err.message : String(err) })
        }
    }

    return (
        <div className="space-y-6">
            <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-2">
                    <h1 className="text-3xl font-bold tracking-tight">{data.name}</h1>
                    <p className="text-muted-foreground">
                        {t("Modules.pages.certificates.detailDescription")}
                    </p>
                </div>
                <Button variant="outline" onClick={() => navigate("/dashboard/certificates")}>
                    {t("Modules.backToCertificates")}
                </Button>
            </div>
            <dl className="grid gap-4 rounded-lg border p-4 sm:grid-cols-2">
                <DetailField
                    label={t("Modules.pages.certificates.status")}
                    value={t(`Modules.certificateStatus.${data.status}`, data.status)}
                />
                <DetailField label={t("Modules.pages.certificates.subject")} value={data.subject} />
                <DetailField label={t("Modules.pages.certificates.issuer")} value={data.issuer} />
                <DetailField
                    label={t("Modules.pages.certificates.serial")}
                    value={data.serial_number}
                />
                <DetailField
                    label={t("Modules.pages.certificates.validFrom")}
                    value={formatDate(data.not_before)}
                />
                <DetailField
                    label={t("Modules.pages.certificates.expires")}
                    value={formatDate(data.not_after)}
                />
                <DetailField
                    label={t("Modules.pages.certificates.domains")}
                    value={[...(data.dns_names ?? []), ...(data.ip_addresses ?? [])].join(", ")}
                />
            </dl>
            <div className="flex flex-wrap gap-2">
                <Button onClick={() => download(false)}>
                    {t("Modules.pages.certificates.downloadCertificate")}
                </Button>
                <Button variant="outline" onClick={() => download(true)}>
                    {t("Modules.pages.certificates.downloadPrivate")}
                </Button>
            </div>
            <p className="text-sm text-muted-foreground">
                {t("Modules.pages.certificates.privateKeyNotice")}
            </p>
        </div>
    )
}

function DetailField({ label, value }: { label: string; value: string }) {
    return (
        <div>
            <dt className="text-xs font-medium uppercase text-muted-foreground">{label}</dt>
            <dd className="mt-1 break-words">{value || "—"}</dd>
        </div>
    )
}
