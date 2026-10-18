import { ModuleNavigation } from "@/components/module-navigation"
import i18n from "@/lib/i18n"
import { moduleRoutes } from "@/routes/modules/routes"
import ProtectedRoute from "@/routes/protect"
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react"
import { Outlet, RouterProvider, createMemoryRouter } from "react-router-dom"
import { afterEach, beforeEach, expect, test, vi } from "vitest"

let mockProfile: { id: number; role?: number } | undefined
let mockLoading = false
vi.mock("@/hooks/useAuth", () => ({
    useAuth: () => ({ profile: mockProfile, loading: mockLoading }),
}))

beforeEach(async () => {
    mockProfile = { id: 1, role: 0 }
    mockLoading = false
    await i18n.changeLanguage("en-US")
})

afterEach(cleanup)

async function renderPath(path: string, routes = moduleRoutes) {
    const router = createMemoryRouter(
        [
            {
                path: "/dashboard",
                element: (
                    <ProtectedRoute>
                        <ModuleNavigation />
                        <Outlet />
                    </ProtectedRoute>
                ),
                children: [{ path: "login", element: <h1>Login</h1> }, ...routes],
            },
        ],
        { initialEntries: [path] },
    )
    await act(async () => {
        render(<RouterProvider router={router} />)
    })
    return router
}

test.each([
    ["/dashboard/dns", "DNS"],
    ["/dashboard/credentials", "Credentials"],
    ["/dashboard/certificates", "Certificate assets"],
    ["/dashboard/certificates/workflows", "Certificate workflows"],
    ["/dashboard/certificates/workflows/workflow-42/design", "Workflow design"],
    ["/dashboard/certificates/workflows/workflow-42/runs", "Run history"],
    ["/dashboard/certificates/presets", "Certificate presets"],
])("direct entry to %s renders the intended page", async (path, title) => {
    await renderPath(path)
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(title)
    if (path === "/dashboard/certificates") {
        expect(screen.getByRole("button", { name: "Upload certificate" })).toBeTruthy()
    } else {
        expect(screen.getByRole("heading", { name: "Feature not connected yet" })).toBeTruthy()
    }
})

test("deep links select only the workflow section and preserve the ID during navigation", async () => {
    const router = await renderPath("/dashboard/certificates/workflows/team%20alpha/design")
    const globalNav = screen.getByRole("navigation", { name: "Platform modules" })
    expect(
        within(globalNav).getByRole("link", { name: "Certificates" }).getAttribute("aria-current"),
    ).toBe("page")
    const certificateNav = screen.getByRole("navigation", { name: "Certificate navigation" })
    expect(
        within(certificateNav)
            .getByRole("link", { name: "Certificate workflows" })
            .getAttribute("aria-current"),
    ).toBe("page")
    expect(
        within(certificateNav)
            .getByRole("link", { name: "Certificate assets" })
            .hasAttribute("aria-current"),
    ).toBe(false)
    expect(screen.getByText("Workflow ID: team alpha")).toBeTruthy()
    await act(async () => {
        fireEvent.click(screen.getByRole("link", { name: "Run history" }))
    })
    expect(router.state.location.pathname).toBe(
        "/dashboard/certificates/workflows/team%20alpha/runs",
    )
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Run history")
    await act(async () => {
        await router.navigate(-1)
    })
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Workflow design")
    await act(async () => {
        fireEvent.click(screen.getByRole("link", { name: "Back to workflows" }))
    })
    expect(router.state.location.pathname).toBe("/dashboard/certificates/workflows")
})

test.each([1, undefined])("non-admin role %s cannot mount a module page", async (role) => {
    mockProfile = { id: 2, role }
    await renderPath("/dashboard/credentials")
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(
        "Access is currently limited",
    )
    expect(screen.queryByText("Feature not connected yet")).toBeNull()
})

test("auth loading does not mount modules, then unauthenticated users go to login", async () => {
    mockLoading = true
    mockProfile = undefined
    const router = await renderPath("/dashboard/certificates/workflows/42/design")
    expect(screen.queryByRole("main")).toBeNull()
    mockLoading = false
    await act(async () => {
        await router.navigate("/dashboard/credentials")
    })
    expect(router.state.location.pathname).toBe("/dashboard/login")
    expect(screen.getByRole("heading", { name: "Login" })).toBeTruthy()
})

test.each([
    "/dashboard/dns/missing",
    "/dashboard/credentials/missing",
    "/dashboard/certificates/missing",
    "/dashboard/certificates/workflows/42/missing",
])("unknown module path %s uses the local not-found state", async (path) => {
    await renderPath(path)
    expect(screen.getByRole("alert").textContent).toContain("Page not found")
    expect(screen.getByRole("navigation", { name: "Platform modules" })).toBeTruthy()
})

test.each([
    [new Response(null, { status: 403 }), "Access denied"],
    [new Response(null, { status: 404 }), "Page not found"],
    [new Error("private service details"), "Unable to load this page"],
    [null, "Unable to load this page"],
])("module error boundary handles %s within the authenticated layout", async (error, title) => {
    const routes = [
        {
            ...moduleRoutes[0],
            index: false as const,
            children: [
                {
                    ...moduleRoutes[0].children![0],
                    index: false as const,
                    children: [
                        {
                            path: "failure",
                            loader: () => {
                                throw error
                            },
                        },
                    ],
                },
            ],
        },
    ]
    await renderPath("/dashboard/failure", routes)
    expect((await screen.findByRole("alert")).textContent).toContain(title)
    expect(screen.queryByText("private service details")).toBeNull()
    expect(screen.getByRole("navigation", { name: "Platform modules" })).toBeTruthy()
})

test.each([
    ["zh-CN", "证书预设", "功能尚未接入"],
    ["zh-TW", "憑證預設", "功能尚未接入"],
    ["de-DE", "Certificate presets", "Feature not connected yet"],
])("module copy uses %s with the existing English fallback", async (language, title, pending) => {
    await i18n.changeLanguage(language)
    await renderPath("/dashboard/certificates/presets")
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(title)
    expect(screen.getByRole("heading", { name: pending })).toBeTruthy()
})
