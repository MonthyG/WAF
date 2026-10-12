import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = {
  title: 'CloudInside · Web Application Firewall',
  description: 'Protect and manage your web applications.',
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
