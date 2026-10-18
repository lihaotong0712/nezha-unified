import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { useAuth } from "@/hooks/useAuth"
import { cn } from "@/lib/utils"
import { LockKeyhole } from "lucide-react"
import { useTranslation } from "react-i18next"
import { Link, NavLink, Navigate, Outlet, useParams } from "react-router-dom"

export function ModuleLayout() {
    const { t } = useTranslation()
    const { profile, loading } = useAuth()

    if (loading) return null
    if (!profile) return <Navigate to="/dashboard/login" replace />

    // Temporary UI gate until resource authorization is available. Business
    // endpoints must enforce their own authorization when they are introduced.
    if (profile.role !== 0) {
        return (
            <Card className="mx-3 mt-6">
                <CardContent className="space-y-4 pt-6 text-center">
                    <LockKeyhole
                        aria-hidden="true"
                        className="mx-auto h-10 w-10 text-muted-foreground"
                    />
                    <h1 className="text-2xl font-semibold">{t("Modules.access.title")}</h1>
                    <p className="text-muted-foreground">{t("Modules.access.description")}</p>
                    <Button asChild variant="outline">
                        <Link to="/dashboard">{t("Modules.backToDashboard")}</Link>
                    </Button>
                </CardContent>
            </Card>
        )
    }

    return (
        <main className="space-y-6 px-3 py-6">
            <Outlet />
        </main>
    )
}

function SectionNavigation({
    label,
    links,
}: {
    label: string
    links: { path: string; label: string; end?: boolean }[]
}) {
    const { t } = useTranslation()

    return (
        <nav aria-label={t(label)} className="flex flex-wrap gap-2 border-b pb-3">
            {links.map((link) => (
                <NavLink
                    key={link.path}
                    to={link.path}
                    end={link.end}
                    className={({ isActive }) =>
                        cn(
                            "rounded-md px-3 py-2 text-sm font-medium transition-colors hover:bg-accent",
                            isActive ? "bg-accent text-accent-foreground" : "text-muted-foreground",
                        )
                    }
                >
                    {t(link.label)}
                </NavLink>
            ))}
        </nav>
    )
}

export function CertificateLayout() {
    return (
        <>
            <SectionNavigation
                label="Modules.certificateNavigation"
                links={[
                    {
                        path: "/dashboard/certificates",
                        label: "Modules.pages.certificates.title",
                        end: true,
                    },
                    {
                        path: "/dashboard/certificates/workflows",
                        label: "Modules.pages.workflows.title",
                    },
                    {
                        path: "/dashboard/certificates/presets",
                        label: "Modules.pages.presets.title",
                        end: true,
                    },
                ]}
            />
            <Outlet />
        </>
    )
}

export function WorkflowLayout() {
    const { t } = useTranslation()
    const { id } = useParams()
    const path = `/dashboard/certificates/workflows/${encodeURIComponent(id!)}`

    return (
        <>
            <div className="flex flex-wrap items-center justify-between gap-3">
                <Button asChild variant="outline" size="sm">
                    <Link to="/dashboard/certificates/workflows">
                        {t("Modules.backToWorkflows")}
                    </Link>
                </Button>
                <p className="min-w-0 break-all text-sm text-muted-foreground">
                    {t("Modules.workflowId", { id })}
                </p>
            </div>
            <SectionNavigation
                label="Modules.workflowNavigation"
                links={[
                    { path: `${path}/design`, label: "Modules.pages.design.title", end: true },
                    { path: `${path}/runs`, label: "Modules.pages.runs.title", end: true },
                ]}
            />
            <Outlet />
        </>
    )
}
