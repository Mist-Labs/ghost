import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Ghost — Proactive Protocol Defense",
  description:
    "Ghost gives protocols continuous anomaly monitoring, proactive exploit discovery, live incident response, and court-ready evidence packaging.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="font-body antialiased">{children}</body>
    </html>
  );
}
