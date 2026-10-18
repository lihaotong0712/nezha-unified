import { cn } from "@/lib/utils"
import { useTranslation } from "react-i18next"
import { NavLink } from "react-router-dom"

const modules = [
    { path: "/dashboard/dns", label: "Modules.pages.dns.title" },
    { path: "/dashboard/credentials", label: "Modules.pages.credentials.title" },
    { path: "/dashboard/certificates", label: "Modules.certificates" },
]

export function ModuleNavigation({ onNavigate }: { onNavigate?: () => void }) {
    const { t } = useTranslation()

    return (
        <nav aria-label={t("Modules.navigation")} className="flex flex-wrap gap-1 py-2">
            {modules.map(({ path, label }) => (
                <NavLink
                    key={path}
                    to={path}
                    onClick={onNavigate}
                    className={({ isActive }) =>
                        cn(
                            "rounded-md px-4 py-2 text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground",
                            isActive ? "bg-accent text-accent-foreground" : "text-muted-foreground",
                        )
                    }
                >
                    {t(label)}
                </NavLink>
            ))}
        </nav>
    )
}
