import os
import tempfile
import requests
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from core.engine import APIScanEngine
from core.models import ScanConfig, ScanTarget
from repositories.cosmos_scan_repository import CosmosScanRepository
from repositories.blob_report_repository import BlobReportRepository


class ScanService:

    def __init__(
        self,
        repository: Optional[CosmosScanRepository] = None,
        blob_repository: Optional[BlobReportRepository] = None
    ):

        self.engine = APIScanEngine(
            ScanConfig(
                timeout=2,
                rate_limit_attempts=2,
                verbose=False,
                enable_bruteforce=True
            )
        )

        # CosmosDB
        self.repository = repository or CosmosScanRepository()

        # Blob Storage
        self.blob_repository = blob_repository

    # ==========================================================
    # DOWNLOAD OPENAPI SPEC
    # ==========================================================
    def _download_spec(self, spec_url: str) -> str:

        response = requests.get(spec_url, timeout=10)
        response.raise_for_status()

        suffix = ".json"

        if spec_url.endswith(".yaml") or spec_url.endswith(".yml"):
            suffix = ".yaml"

        temp_file = tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix,
            mode="w",
            encoding="utf-8"
        )

        temp_file.write(response.text)
        temp_file.close()

        return temp_file.name

    # ==========================================================
    # CREATE SCAN JOB
    # ==========================================================
    def create_scan_job(self, target: ScanTarget) -> dict:

        scan_id = str(uuid.uuid4())

        scan_job = {
            "scan_id": scan_id,

            "target_url": target.base_url,

            "status": "pending",

            "final_score": 0,
            "grade": "Pending",

            "started_at": None,
            "finished_at": None,

            "duration_ms": 0,

            "spec_url": target.spec_url,

            "error_message": None,

            "discovered_endpoints_count": 0,

            "findings_count": 0,

            "findings": [],

            "category_scores": {},

            "report_url": None,

            "created_at": datetime.now(timezone.utc).isoformat()
        }

        self.repository.save(scan_job)

        return scan_job

    # ==========================================================
    # EXECUTE SCAN
    # ==========================================================
    def execute_scan_job(self, scan_id: str, target: ScanTarget) -> None:

        temp_spec_path = None

        started_dt = datetime.now(timezone.utc)

        # ----------------------------------------
        # UPDATE STATUS -> RUNNING
        # ----------------------------------------
        self.repository.update(
            scan_id,
            {
                "status": "running",
                "started_at": started_dt.isoformat(),
                "error_message": None
            }
        )

        try:

            # ----------------------------------------
            # DOWNLOAD SPEC
            # ----------------------------------------
            if target.spec_url:

                temp_spec_path = self._download_spec(target.spec_url)

                target.spec_path = temp_spec_path

            # ----------------------------------------
            # RUN ENGINE
            # ----------------------------------------
            result = self.engine.run(target)

            # ======================================================
            # FULL REPORT (BLOB STORAGE)
            # ======================================================
            full_report = {
                "scan_id": scan_id,

                "target_url": target.base_url,

                "findings": [
                    f.to_dict() for f in result.findings
                ],

                "category_scores": result.category_scores,

                "final_score": result.final_score,

                "grade": result.grade,

                "started_at": result.started_at,

                "finished_at": result.finished_at,

                "duration_ms": result.duration_ms,

                "exported_at": datetime.now(
                    timezone.utc
                ).isoformat()
            }

            report_url = None

            if self.blob_repository:

                report_url = self.blob_repository.save_report(
                    scan_id,
                    full_report
                )

            # ======================================================
            # COSMOS DOCUMENT
            # ======================================================
            completed_data = {

                # ----------------------------------------
                # IDENTIFICATION
                # ----------------------------------------
                "scan_id": scan_id,

                "target_url": target.base_url,

                # ----------------------------------------
                # STATUS
                # ----------------------------------------
                "status": "completed",

                # ----------------------------------------
                # SCORE
                # ----------------------------------------
                "final_score": result.final_score,

                "grade": result.grade,

                # ----------------------------------------
                # TIMESTAMPS
                # ----------------------------------------
                "started_at": result.started_at,

                "finished_at": result.finished_at,

                "duration_ms": result.duration_ms,

                # ----------------------------------------
                # ERRORS
                # ----------------------------------------
                "error_message": None,

                # ----------------------------------------
                # ENDPOINTS
                # ----------------------------------------
                "discovered_endpoints_count":
                    result.discovered_endpoints_count,

                # ----------------------------------------
                # FINDINGS
                # ----------------------------------------
                "findings_count":
                    len(result.findings),

                "findings": [
                    {
                        **f.to_dict(),

                        # fallback para UI
                        "severity":
                            getattr(f, "severity", "UNKNOWN"),

                        "endpoint":
                            getattr(f, "endpoint", "Unknown"),

                        "title":
                            getattr(f, "title", "Unknown"),

                        "description":
                            getattr(f, "description", ""),

                        "recommendation":
                            getattr(f, "recommendation", ""),

                        "category":
                            getattr(f, "category", "General")
                    }

                    for f in result.findings
                ],

                # ----------------------------------------
                # CATEGORY SCORES
                # ----------------------------------------
                "category_scores":
                    result.category_scores,

                # ----------------------------------------
                # BLOB REPORT
                # ----------------------------------------
                "report_url": report_url,

                # ----------------------------------------
                # CREATED
                # ----------------------------------------
                "created_at":
                    datetime.now(
                        timezone.utc
                    ).isoformat()
            }

            # ----------------------------------------
            # SAVE TO COSMOS
            # ----------------------------------------
            self.repository.update(
                scan_id,
                completed_data
            )

        except Exception as e:

            finished_dt = datetime.now(timezone.utc)

            duration_ms = int(
                (finished_dt - started_dt).total_seconds() * 1000
            )

            # ----------------------------------------
            # FAILED DOCUMENT
            # ----------------------------------------
            failed_data = {

                "status": "failed",

                "finished_at":
                    finished_dt.isoformat(),

                "duration_ms":
                    duration_ms,

                "error_message":
                    str(e)
            }

            self.repository.update(
                scan_id,
                failed_data
            )

            # ----------------------------------------
            # SAVE LOG TO BLOB
            # ----------------------------------------
            if self.blob_repository:

                self.blob_repository.save_log(
                    scan_id,
                    (
                        f"Scan {scan_id} falhou em "
                        f"{finished_dt.isoformat()}\n"
                        f"Erro: {e}"
                    )
                )

        finally:

            # ----------------------------------------
            # CLEAN TEMP FILE
            # ----------------------------------------
            if (
                temp_spec_path
                and os.path.exists(temp_spec_path)
            ):
                os.remove(temp_spec_path)

    # ==========================================================
    # LIST SCANS
    # ==========================================================
    def list_scans(self) -> List[dict]:

        return self.repository.list_all()

    # ==========================================================
    # GET SCAN BY ID
    # ==========================================================
    def get_scan_by_id(
        self,
        scan_id: str
    ) -> Optional[dict]:

        return self.repository.get_by_id(scan_id)

    # ==========================================================
    # GET SCAN STATUS
    # ==========================================================
    def get_scan_status(
        self,
        scan_id: str
    ) -> Optional[dict]:

        scan = self.repository.get_by_id(scan_id)

        if not scan:
            return None

        return {

            "scan_id":
                scan["scan_id"],

            "status":
                scan["status"],

            "started_at":
                scan["started_at"],

            "finished_at":
                scan["finished_at"],

            "duration_ms":
                scan["duration_ms"],

            "error_message":
                scan.get("error_message"),

            "discovered_endpoints_count":
                scan.get(
                    "discovered_endpoints_count",
                    0
                ),

            "findings_count":
                scan.get(
                    "findings_count",
                    0
                ),

            "final_score":
                scan.get(
                    "final_score",
                    0
                ),

            "grade":
                scan.get(
                    "grade",
                    "Unknown"
                )
        }
