import csv
import hashlib
import sqlite3
from pathlib import Path

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE

from .extract import extract

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, started TEXT DEFAULT CURRENT_TIMESTAMP, label TEXT);
CREATE TABLE IF NOT EXISTS resources(id INTEGER PRIMARY KEY, run_id INTEGER, site TEXT, url TEXT,
 kind TEXT, status INTEGER, evidence_path TEXT, error TEXT, UNIQUE(run_id,site,url));
CREATE TABLE IF NOT EXISTS text_views(resource_id INTEGER PRIMARY KEY,path TEXT);
CREATE TABLE IF NOT EXISTS edges(run_id INTEGER,site TEXT,parent TEXT,child TEXT,relation TEXT,
 UNIQUE(run_id,site,parent,child,relation));
CREATE TABLE IF NOT EXISTS findings(resource_id INTEGER,host TEXT,registered TEXT,host_type TEXT,
 start INTEGER,end INTEGER,line INTEGER,col INTEGER,source TEXT,method TEXT,evidence TEXT,
 UNIQUE(resource_id,host,start,end,source));
CREATE TABLE IF NOT EXISTS queue(run_id INTEGER,site TEXT,url TEXT,depth INTEGER,asset INTEGER,
 state TEXT DEFAULT 'pending',error TEXT, UNIQUE(run_id,site,url));
CREATE TABLE IF NOT EXISTS run_configs(run_id INTEGER PRIMARY KEY,config TEXT);
CREATE TABLE IF NOT EXISTS run_events(id INTEGER PRIMARY KEY,run_id INTEGER,
 time TEXT DEFAULT CURRENT_TIMESTAMP,event TEXT,detail TEXT);
CREATE TABLE IF NOT EXISTS attempts(run_id INTEGER,site TEXT,url TEXT,count INTEGER DEFAULT 0,
 UNIQUE(run_id,site,url));
"""


class Store:
    def __init__(self, directory: str, read_only: bool = False):
        self.directory = Path(directory)
        if read_only:
            database = self.directory / "discovery.sqlite"
            if not database.is_file():
                raise ValueError("results database does not exist; check --output")
            self.db = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
        else:
            self.directory.mkdir(parents=True, exist_ok=True)
            self.db = sqlite3.connect(self.directory / "discovery.sqlite")
        self.db.row_factory = sqlite3.Row
        if not read_only:
            self.db.executescript(SCHEMA)

    def new_run(self, label: str) -> int:
        cursor = self.db.execute("INSERT INTO runs(label) VALUES(?)", (label,))
        self.db.commit()
        return cursor.lastrowid

    def edge(self, run: int, site: str, parent: str, child: str, relation: str):
        self.db.execute(
            "INSERT OR IGNORE INTO edges VALUES(?,?,?,?,?)", (run, site, parent, child, relation)
        )
        self.db.commit()

    def save(
        self,
        run: int,
        site: str,
        url: str,
        body: bytes,
        text: str,
        kind: str,
        status: int = 200,
        error: str = "",
    ):
        digest = hashlib.sha256(body).hexdigest()
        folder = self.directory / "evidence"
        folder.mkdir(exist_ok=True)
        path = folder / digest
        path.write_bytes(body)
        self.db.execute(
            "INSERT INTO resources(run_id,site,url,kind,status,evidence_path,error) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(run_id,site,url) DO UPDATE SET kind=excluded.kind,status=excluded.status,"
            "evidence_path=excluded.evidence_path,error=excluded.error",
            (run, site, url, kind, status, str(path.relative_to(self.directory)), error),
        )
        resource = self.db.execute(
            "SELECT id FROM resources WHERE run_id=? AND site=? AND url=?", (run, site, url)
        ).fetchone()[0]
        decoded = text.encode("utf-8")
        text_path = folder / (hashlib.sha256(decoded).hexdigest() + ".utf8")
        text_path.write_bytes(decoded)
        self.db.execute(
            "INSERT OR REPLACE INTO text_views VALUES(?,?)",
            (resource, str(text_path.relative_to(self.directory))),
        )
        self.db.execute("DELETE FROM findings WHERE resource_id=?", (resource,))
        for mention in extract(text, kind):
            self.db.execute(
                "INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    resource,
                    mention.host,
                    mention.registered,
                    mention.host_type,
                    mention.start,
                    mention.end,
                    mention.line,
                    mention.column,
                    mention.source,
                    mention.method,
                    mention.evidence,
                ),
            )
        self.db.commit()

    def export(self):
        queries = {
            "域名汇总": "SELECT r.run_id,r.site,f.host,f.registered,f.host_type,COUNT(*) AS occurrences FROM findings f JOIN resources r ON r.id=f.resource_id GROUP BY r.run_id,r.site,f.host",
            "发现明细": "SELECT r.run_id,r.site,r.url,f.host,f.line,f.col,f.source,f.method,f.evidence,r.evidence_path,t.path AS decoded_text_path,f.start,f.end FROM findings f JOIN resources r ON r.id=f.resource_id LEFT JOIN text_views t ON t.resource_id=r.id ORDER BY r.run_id,r.site,r.url,f.start",
            "扫描覆盖": "SELECT q.run_id,q.site,q.state,COUNT(*) AS urls, GROUP_CONCAT(DISTINCT q.error) AS errors FROM queue q GROUP BY q.run_id,q.site,q.state",
            "引用关系": "SELECT * FROM edges ORDER BY run_id,site,parent,child",
        }
        workbook = Workbook()
        workbook.remove(workbook.active)
        for title, query in queries.items():
            cursor = self.db.execute(query)
            header = [field[0] for field in cursor.description]
            rows = cursor.fetchall()
            with (self.directory / f"{title}.csv").open(
                "w", encoding="utf-8-sig", newline=""
            ) as stream:
                writer = csv.writer(stream)
                writer.writerow(header)
                writer.writerows(rows)
            sheet = workbook.create_sheet(title)
            sheet.append(header)
            for row in rows:
                sheet.append(
                    [
                        ILLEGAL_CHARACTERS_RE.sub("", str(cell))[:32767]
                        if isinstance(cell, str)
                        else cell
                        for cell in row
                    ]
                )
                # Evidence is untrusted text, never an Excel formula.
                for cell in sheet[sheet.max_row]:
                    if cell.data_type == "f":
                        cell.data_type = "s"
            sheet.freeze_panes = "A2"
            sheet.auto_filter.ref = sheet.dimensions
        workbook.save(self.directory / "results.xlsx")

    def close(self):
        self.db.close()
