N&N BEDSHEETS & BLANKETS — WEBSITE PROJECT
==========================================

INCLUDED
- Premium responsive traditional-luxury design (burgundy, cream, antique gold)
- User registration/login; password hashes stored securely
- SQLite database created automatically on first run
- 500 shop records and 1,000 embedded images extracted from your Excel file
- Search by shop, market, address, phone and product; market/product filters
- Shop detail pages and admin dashboard
- Admin can add new shop records

RUN ON WINDOWS
1. Install Python 3.10+ from https://www.python.org/downloads/ and enable Add Python to PATH.
2. Extract this ZIP to a normal folder.
3. Double-click run_windows.bat; it installs Flask and starts the app.
4. Open http://127.0.0.1:5000 in your browser.

DEMO ADMIN (for local setup only)
Email: admin@nandn.local
Password: NandN@2026

IMPORTANT
- This is local by default. Other people cannot use it from their own devices/internet until you deploy it to hosting and configure production security, HTTPS, a persistent secret key and backups.
- Data is stored in nandn.db. Back up this file regularly.
- Replace demo admin credentials before public deployment.
- Average Price (PKR) cells in the supplied workbook are date-typed by Excel; values are imported as their underlying numeric serials. Verify those prices against your source before using them commercially.
- Verification labels are copied from the workbook and have not been independently checked.

CREDITS
Developed by: M. SAMEER · M. BILAL · M. HAMZA
PROJECT OF DR NADEEM NAZIR
