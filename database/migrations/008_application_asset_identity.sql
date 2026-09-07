BEGIN;

CREATE UNIQUE INDEX uq_asset_identifiers_application_active
    ON asset_identifiers (
        tenant_code,
        identifier_type,
        normalized_value
    )
    WHERE
        is_active = TRUE
        AND identifier_type = 'APPLICATION_ID';

COMMIT;
