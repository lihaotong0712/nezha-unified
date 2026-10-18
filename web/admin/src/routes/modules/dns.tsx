import { listDNSRecords, listDNSZones, DNSRecord, DNSZone } from "@/api/dns"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
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
import { FormEvent, useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import useSWR from "swr"

const ttlText = (record: DNSRecord) =>
    record.ttl?.mode === "automatic" ? "automatic" : `${record.ttl?.seconds ?? 0}s`

export default function DNSPage() {
    const { t } = useTranslation()
    const [selected, setSelected] = useState<DNSZone>()
    const [name, setName] = useState("")
    const [type, setType] = useState("")
    const { data: zones, error: zonesError, isLoading: zonesLoading } = useSWR<DNSZone[]>(
        "/api/v1/dns/zones",
        listDNSZones,
    )
    const recordsKey = selected
        ? ["/api/v1/dns/zones", selected.ref.id, "records", name, type]
        : null
    const {
        data: recordsPage,
        error: recordsError,
        isLoading: recordsLoading,
        mutate: reloadRecords,
    } = useSWR(recordsKey, () => listDNSRecords(selected!.ref.id, { name, type }))

    useEffect(() => {
        if (zones?.length && !selected) setSelected(zones[0])
    }, [zones, selected])
    useEffect(() => {
        if (zonesError) toast(t("Error"), { description: zonesError.message })
    }, [zonesError, t])
    useEffect(() => {
        if (recordsError) toast(t("Error"), { description: recordsError.message })
    }, [recordsError, t])

    const applyFilter = (event: FormEvent) => {
        event.preventDefault()
        void reloadRecords()
    }

    return (
        <div className="space-y-6">
            <div className="space-y-2">
                <h1 className="text-3xl font-bold tracking-tight">{t("Modules.pages.dns.title")}</h1>
                <p className="text-muted-foreground">{t("Modules.pages.dns.description")}</p>
            </div>
            {zonesLoading ? (
                <p className="text-muted-foreground">{t("Loading")}...</p>
            ) : !zones?.length ? (
                <Card>
                    <CardContent className="py-8 text-center text-muted-foreground">
                        {t("Modules.pages.dns.emptyZones")}
                    </CardContent>
                </Card>
            ) : (
                <div className="grid gap-6 lg:grid-cols-[minmax(14rem,20rem)_1fr]">
                    <Card>
                        <CardHeader><CardTitle>{t("Modules.pages.dns.zones")}</CardTitle></CardHeader>
                        <CardContent className="space-y-2">
                            {zones.map((zone) => (
                                <Button
                                    key={zone.ref.id}
                                    variant={selected?.ref.id === zone.ref.id ? "secondary" : "ghost"}
                                    className="h-auto w-full justify-start px-3 py-2 text-left"
                                    onClick={() => setSelected(zone)}
                                >
                                    <span className="min-w-0">
                                        <span className="block truncate font-medium">{zone.remote.name}</span>
                                        <span className="block truncate text-xs text-muted-foreground">{zone.provider}</span>
                                    </span>
                                </Button>
                            ))}
                        </CardContent>
                    </Card>
                    <Card>
                        <CardHeader>
                            <div className="flex flex-wrap items-center justify-between gap-3">
                                <CardTitle>{selected?.remote.name}</CardTitle>
                                <form className="flex flex-wrap items-end gap-2" onSubmit={applyFilter}>
                                    <div>
                                        <Label htmlFor="dns-record-name">{t("Name")}</Label>
                                        <Input id="dns-record-name" value={name} onChange={(e) => setName(e.target.value)} />
                                    </div>
                                    <div>
                                        <Label htmlFor="dns-record-type">{t("Type")}</Label>
                                        <Input id="dns-record-type" value={type} onChange={(e) => setType(e.target.value.toUpperCase())} />
                                    </div>
                                    <Button type="submit" variant="outline">{t("Search")}</Button>
                                </form>
                            </div>
                        </CardHeader>
                        <CardContent>
                            {recordsLoading ? <p className="text-muted-foreground">{t("Loading")}...</p> : (
                                <Table>
                                    <TableHeader><TableRow>
                                        <TableHead>{t("Name")}</TableHead>
                                        <TableHead>{t("Type")}</TableHead>
                                        <TableHead>{t("Value")}</TableHead>
                                        <TableHead>{t("TTL")}</TableHead>
                                    </TableRow></TableHeader>
                                    <TableBody>
                                        {!recordsPage?.items?.length ? <TableRow><TableCell colSpan={4} className="h-24 text-center text-muted-foreground">{t("Modules.pages.dns.emptyRecords")}</TableCell></TableRow> : recordsPage.items.map((record) => (
                                            <TableRow key={record.id}>
                                                <TableCell className="font-medium">{record.name}</TableCell>
                                                <TableCell>{record.type}</TableCell>
                                                <TableCell className="max-w-sm truncate" title={record.value}>{record.value}</TableCell>
                                                <TableCell>{ttlText(record)}</TableCell>
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                            )}
                        </CardContent>
                    </Card>
                </div>
            )}
        </div>
    )
}
