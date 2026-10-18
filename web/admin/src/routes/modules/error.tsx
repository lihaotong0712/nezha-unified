import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { AlertCircle } from "lucide-react"
import { useTranslation } from "react-i18next"
import { Link, isRouteErrorResponse, useRouteError } from "react-router-dom"

export function ModuleErrorState({ status }: { status?: number }) {
    const { t } = useTranslation()
    const state = status === 403 ? "forbidden" : status === 404 ? "notFound" : "unexpected"

    return (
        <Card>
            <CardContent className="space-y-4 pt-6 text-center" role="alert">
                <AlertCircle aria-hidden="true" className="mx-auto h-10 w-10 text-destructive" />
                <h1 className="text-2xl font-semibold">{t(`Modules.errors.${state}.title`)}</h1>
                <p className="text-muted-foreground">{t(`Modules.errors.${state}.description`)}</p>
                <Button asChild variant="outline">
                    <Link to="/dashboard">{t("Modules.backToDashboard")}</Link>
                </Button>
            </CardContent>
        </Card>
    )
}

export function ModuleErrorBoundary() {
    const error = useRouteError()
    return <ModuleErrorState status={isRouteErrorResponse(error) ? error.status : undefined} />
}
