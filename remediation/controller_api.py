#!/usr/bin/env python3

import os

from flask import Flask, jsonify, request

from remediation.shared.config import (
    CONTROLLER_TOKEN,
)
from remediation.shared import db
from remediation.shared.db import (
    ActiveRemediationExistsError,
)

from remediation.controllers.os_patching import (
    OsPatchingController,
)
from remediation.controllers.container_image import (
    ContainerImageController,
)
from remediation.controllers.cis_hardening import (
    CisHardeningController,
)
from remediation.controllers.service_config import (
    ServiceConfigController,
)
from remediation.controllers.web_application import (
    WebApplicationController,
)
from remediation.controllers.file_integrity import (
    FileIntegrityController,
)
from remediation.controllers.security_incident import (
    SecurityIncidentController,
)


app = Flask(__name__)


CONTROLLERS = {
    "os_patching": OsPatchingController(),
    "container_image": ContainerImageController(),
    "cis_hardening": CisHardeningController(),
    "service_config": ServiceConfigController(),
    "web_application": WebApplicationController(),
    "file_integrity": FileIntegrityController(),
    "security_incident": SecurityIncidentController(),
}


def authorised():
    return (
        not CONTROLLER_TOKEN
        or request.headers.get(
            "Authorization"
        )
        == "Bearer " + CONTROLLER_TOKEN
    )


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "service": (
                "regis-remediation-controller"
            ),
            "capabilities": sorted(
                CONTROLLERS
            ),
        }
    )


@app.post("/remediate")
def remediate():
    if not authorised():
        return jsonify(
            {
                "success": False,
                "error": "unauthorised",
            }
        ), 401

    payload = (
        request.get_json(force=True)
        or {}
    )

    capability = payload.get(
        "capability"
    )

    controller = CONTROLLERS.get(
        capability
    )

    if not controller:
        return jsonify(
            {
                "success": False,
                "error": (
                    "Unsupported capability: "
                    f"{capability}"
                ),
            }
        ), 400

    try:
        result = controller.execute(
            payload
        )

        #
        # An approval-gated execution has been
        # accepted and persisted, but remediation
        # has not started.
        #
        if (
            result.get("status")
            == "AWAITING_APPROVAL"
        ):
            return jsonify(result), 202

        return jsonify(result), 200

    except ActiveRemediationExistsError as exc:
        app.logger.info(
            "Duplicate active remediation "
            "rejected: finding_id=%s",
            exc.finding_id,
        )

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 409

    except ValueError as exc:
        app.logger.warning(
            "Invalid remediation request: %s",
            exc,
        )

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 400

    except RuntimeError as exc:
        app.logger.info(
            "Remediation state conflict: %s",
            exc,
        )

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 409

    except Exception:
        app.logger.exception(
            "Controller request failed"
        )

        return jsonify(
            {
                "success": False,
                "error": (
                    "Internal server error"
                ),
            }
        ), 500


@app.post(
    "/executions/<int:execution_id>/approve"
)
def approve_execution(execution_id):
    if not authorised():
        return jsonify(
            {
                "success": False,
                "error": "unauthorised",
            }
        ), 401

    try:
        #
        # Determine the controller from the persisted
        # execution. Do not trust the API caller to
        # provide capability, target, playbook, finding
        # identity, or execution parameters.
        #
        conn = db.connect()

        try:
            with conn:
                execution = db.get_execution(
                    conn,
                    execution_id,
                )

        finally:
            conn.close()

        capability = execution[
            "capability"
        ]

        controller = CONTROLLERS.get(
            capability
        )

        if not controller:
            raise ValueError(
                f"Execution {execution_id} "
                "has unsupported capability "
                f"{capability}"
            )

        result = controller.approve(
            execution_id
        )

        return jsonify(result), 200

    except ValueError as exc:
        app.logger.warning(
            "Invalid approval request: %s",
            exc,
        )

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 400

    except RuntimeError as exc:
        app.logger.info(
            "Approval conflict: %s",
            exc,
        )

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 409

    except Exception:
        app.logger.exception(
            "Approval request failed"
        )

        return jsonify(
            {
                "success": False,
                "error": (
                    "Internal server error"
                ),
            }
        ), 500


@app.post(
    "/executions/<int:execution_id>/cancel"
)
def cancel_execution(execution_id):
    if not authorised():
        return jsonify(
            {
                "success": False,
                "error": "unauthorised",
            }
        ), 401

    conn = None

    try:
        conn = db.connect()

        #
        # db.cancel_awaiting_approval() performs both
        # execution and finding transitions inside this
        # single transaction.
        #
        with conn:
            result = db.cancel_awaiting_approval(
                conn,
                execution_id,
            )

        return jsonify(result), 200

    except ValueError as exc:
        app.logger.warning(
            "Invalid cancellation request: %s",
            exc,
        )

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 400

    except RuntimeError as exc:
        app.logger.info(
            "Cancellation conflict: %s",
            exc,
        )

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 409

    except Exception:
        app.logger.exception(
            "Cancellation request failed"
        )

        return jsonify(
            {
                "success": False,
                "error": (
                    "Internal server error"
                ),
            }
        ), 500

    finally:
        if conn is not None:
            conn.close()



if __name__ == "__main__":
    app.run(
        host=os.getenv(
            "REGIS_CONTROLLER_HOST",
            "127.0.0.1",
        ),
        port=int(
            os.getenv(
                "REGIS_CONTROLLER_PORT",
                "9000",
            )
        ),
    )
