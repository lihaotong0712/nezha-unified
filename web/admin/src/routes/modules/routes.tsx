import { RouteObject } from "react-router-dom"

import { ModuleErrorBoundary, ModuleErrorState } from "./error"
import { CertificateLayout, ModuleLayout, WorkflowLayout } from "./layout"
import { ModulePlaceholder } from "./placeholder"

// Relative to the existing authenticated /dashboard route.
export const moduleRoutes: RouteObject[] = [
    {
        element: <ModuleLayout />,
        children: [
            {
                errorElement: <ModuleErrorBoundary />,
                children: [
                    {
                        path: "dns",
                        children: [
                            { index: true, element: <ModulePlaceholder page="dns" /> },
                            { path: "*", element: <ModuleErrorState status={404} /> },
                        ],
                    },
                    {
                        path: "credentials",
                        children: [
                            { index: true, element: <ModulePlaceholder page="credentials" /> },
                            { path: "*", element: <ModuleErrorState status={404} /> },
                        ],
                    },
                    {
                        path: "certificates",
                        element: <CertificateLayout />,
                        children: [
                            { index: true, element: <ModulePlaceholder page="certificates" /> },
                            { path: "workflows", element: <ModulePlaceholder page="workflows" /> },
                            {
                                path: "workflows/:id",
                                element: <WorkflowLayout />,
                                children: [
                                    {
                                        path: "design",
                                        element: <ModulePlaceholder page="design" />,
                                    },
                                    { path: "runs", element: <ModulePlaceholder page="runs" /> },
                                    { index: true, element: <ModuleErrorState status={404} /> },
                                    { path: "*", element: <ModuleErrorState status={404} /> },
                                ],
                            },
                            { path: "presets", element: <ModulePlaceholder page="presets" /> },
                            { path: "*", element: <ModuleErrorState status={404} /> },
                        ],
                    },
                ],
            },
        ],
    },
]
