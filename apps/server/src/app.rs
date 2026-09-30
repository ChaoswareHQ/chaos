use leptos::prelude::*;
use leptos_meta::{provide_meta_context, MetaTags, Stylesheet, Title};
use leptos_router::{
    components::{Route, Router, Routes},
    StaticSegment,
};

#[cfg(feature = "ssr")]
pub use leptos_config::LeptosOptions;

#[cfg(feature = "ssr")]
pub struct ServerConfig {
    pub leptos_options: LeptosOptions,
}

#[cfg(feature = "ssr")]
pub fn get_configuration(_cx: Option<()>) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::net::SocketAddr;

    // For SSR builds, read the configuration from Cargo.toml metadata
    // In production, this would read from environment variables or a config file
    let leptos_options = LeptosOptions::builder()
        .output_name(Arc::from("server"))
        .site_root(Arc::from("target/site"))
        .site_pkg_dir(Arc::from("pkg"))
        .site_addr("127.0.0.1:3000".parse::<SocketAddr>()?)
        .reload_port(3001)
        .build();

    Ok(ServerConfig { leptos_options })
}

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <title>Chaos</title>
                <link rel="stylesheet" href="/style.css"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Title text="Chaos"/>
        <Stylesheet id="leptos" href="/pkg/server.css"/>
        <Router>
            <main>
                <Routes fallback=|| "Page not found.".into_view()>
                    <Route path=StaticSegment("") view=HomePage/>
                    <Route path=StaticSegment("dashboard") view=Dashboard/>
                    <Route path=StaticSegment("agents") view=Agents/>
                    <Route path=StaticSegment("profile") view=Profile/>
                    <Route path=StaticSegment("settings") view=Settings/>
                </Routes>
            </main>
        </Router>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    view! {
        <Navbar/>
        <div class="page-content">
            <h1>"Welcome to Chaos"</h1>
            <p>"Chaos monitoring and management platform"</p>
        </div>
    }
}

#[component]
fn Dashboard() -> impl IntoView {
    view! {
        <Navbar/>
        <div class="page-content">
            <h1>"Dashboard"</h1>
            <p>"System dashboard and overview"</p>
        </div>
    }
}

#[component]
fn Agents() -> impl IntoView {
    view! {
        <Navbar/>
        <div class="page-content">
            <h1>"Agents"</h1>
            <p>"Manage and monitor agents"</p>
        </div>
    }
}

#[component]
fn Profile() -> impl IntoView {
    view! {
        <Navbar/>
        <div class="page-content">
            <h1>"Profile"</h1>
            <p>"User profile settings"</p>
        </div>
    }
}

#[component]
fn Settings() -> impl IntoView {
    view! {
        <Navbar/>
        <div class="page-content">
            <h1>"Settings"</h1>
            <p>"Application settings"</p>
        </div>
    }
}

#[component]
fn Navbar() -> impl IntoView {
    view! {
        <nav class="navbar">
            <a href="/" class="navbar__logo">"CHAOS"</a>

            <ul class="navbar__menu">
                <li class="navbar__item">
                    <details class="navbar__dropdown">
                        <summary class="navbar__link">"Overview"</summary>

                        <ul class="navbar__submenu">
                            <li>
                                <a href="/dashboard" class="navbar__sublink">"Dashboard"</a>
                            </li>
                            <li>
                                <a href="/agents" class="navbar__sublink">"Agents"</a>
                            </li>
                        </ul>
                    </details>
                </li>
            </ul>

            <details class="navbar__dropdown navbar__dropdown--end">
                <summary class="navbar__link navbar__profile" aria-label="Profile">
                    <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="20"
                        height="20"
                        fill="currentColor"
                        viewBox="0 0 256 256"
                        aria-hidden="true"
                    >
                        <path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24ZM74.08,197.5a64,64,0,0,1,107.84,0,87.83,87.83,0,0,1-107.84,0ZM96,120a32,32,0,1,1,32,32A32,32,0,0,1,96,120Zm97.76,66.41a79.66,79.66,0,0,0-36.06-28.75,48,48,0,1,0-59.4,0,79.66,79.66,0,0,0-36.06,28.75,88,88,0,1,1,131.52,0Z"/>
                    </svg>
                </summary>

                <ul class="navbar__submenu">
                    <li>
                        <a href="/profile" class="navbar__sublink">"Profile"</a>
                    </li>
                    <li>
                        <a href="/settings" class="navbar__sublink">"Settings"</a>
                    </li>
                    <li>
                        <a href="/logout" class="navbar__sublink">"Logout"</a>
                    </li>
                </ul>
            </details>
        </nav>
    }
}