import { Card, CardContent } from "@/components/ui/card"
import { Blocks } from "lucide-react"
import { useTranslation } from "react-i18next"

export type ModulePage =
    "dns" | "credentials" | "certificates" | "workflows" | "design" | "runs" | "presets"

export function ModulePlaceholder({ page }: { page: ModulePage }) {
    const { t } = useTranslation()

    return (
        <>
            <div className="space-y-2">
                <h1 className="text-3xl font-bold tracking-tight">
                    {t(`Modules.pages.${page}.title`)}
                </h1>
                <p className="text-muted-foreground">{t(`Modules.pages.${page}.description`)}</p>
            </div>
            <Card>
                <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
                    <Blocks aria-hidden="true" className="h-10 w-10 text-muted-foreground" />
                    <h2 className="text-lg font-semibold">{t("Modules.pending.title")}</h2>
                    <p className="max-w-lg text-sm text-muted-foreground">
                        {t(`Modules.pages.${page}.pending`)}
                    </p>
                </CardContent>
            </Card>
        </>
    )
}
