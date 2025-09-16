"""
Configuration management endpoints for Kong Guard AI
Auto-generated from Kong plugin schema analysis
"""

from datetime import datetime
from typing import Any

from app.core.dependencies import get_current_user
from app.core.dependencies import require_admin
from app.models.schemas import ConfigurationResponse
from app.models.schemas import PartialConfiguration
from app.models.schemas import PluginConfiguration
from app.services.configuration_service import ConfigurationService
from app.services.kong_integration import KongIntegrationService
from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status

router = APIRouter()


@router.get("/", response_model=PluginConfiguration)
async def get_configuration(current_user: dict = Depends(get_current_user)) -> PluginConfiguration:
    """
    Get current Kong Guard AI plugin configuration.

    Returns the active configuration including all security settings,
    thresholds, and feature flags.
    """
    try:
        config = await ConfigurationService.get_current_configuration()
        return config
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to retrieve configuration: {str(e)}"
        )


@router.put("/", response_model=ConfigurationResponse)
async def update_configuration(
    config: PluginConfiguration, current_user: dict = Depends(require_admin)
) -> ConfigurationResponse:
    """
    Update complete Kong Guard AI plugin configuration.

    This endpoint replaces the entire configuration. Use PATCH for partial updates.

    **Security Note**: Requires admin privileges. Changes are validated before applying.
    """
    try:
        # Validate configuration
        validation_result = await ConfigurationService.validate_configuration(config)
        if not validation_result.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid configuration: {validation_result.errors}"
            )

        # Apply configuration to Kong
        await KongIntegrationService.update_plugin_config(config.dict())

        # Store configuration
        updated_config = await ConfigurationService.update_configuration(config)

        return ConfigurationResponse(
            status="success",
            message="Configuration updated successfully",
            configuration=updated_config,
            timestamp=datetime.utcnow(),
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update configuration: {str(e)}"
        )


@router.patch("/", response_model=ConfigurationResponse)
async def patch_configuration(
    config: PartialConfiguration, current_user: dict = Depends(require_admin)
) -> ConfigurationResponse:
    """
    Partially update Kong Guard AI plugin configuration.

    Only provided fields will be updated. Omitted fields remain unchanged.

    **Security Note**: Requires admin privileges.
    """
    try:
        # Get current configuration
        current_config = await ConfigurationService.get_current_configuration()

        # Merge with updates
        update_data = config.dict(exclude_unset=True)
        updated_config_dict = current_config.dict()
        updated_config_dict.update(update_data)

        # Create new configuration object
        updated_config = PluginConfiguration(**updated_config_dict)

        # Validate merged configuration
        validation_result = await ConfigurationService.validate_configuration(updated_config)
        if not validation_result.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid configuration: {validation_result.errors}"
            )

        # Apply to Kong
        await KongIntegrationService.update_plugin_config(updated_config.dict())

        # Store configuration
        final_config = await ConfigurationService.update_configuration(updated_config)

        return ConfigurationResponse(
            status="success",
            message="Configuration partially updated",
            configuration=final_config,
            timestamp=datetime.utcnow(),
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update configuration: {str(e)}"
        )


@router.post("/validate", response_model=dict[str, Any])
async def validate_configuration(
    config: PluginConfiguration, current_user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """
    Validate a configuration without applying it.

    Useful for testing configuration changes before deployment.
    """
    try:
        validation_result = await ConfigurationService.validate_configuration(config)

        return {
            "is_valid": validation_result.is_valid,
            "errors": validation_result.errors if not validation_result.is_valid else [],
            "warnings": validation_result.warnings,
            "suggestions": validation_result.suggestions,
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Validation failed: {str(e)}")


@router.post("/reset", response_model=ConfigurationResponse)
async def reset_configuration(current_user: dict = Depends(require_admin)) -> ConfigurationResponse:
    """
    Reset configuration to safe defaults.

    This will enable dry_run_mode and set conservative thresholds.

    **Security Note**: Requires admin privileges.
    """
    try:
        # Get default configuration
        default_config = await ConfigurationService.get_default_configuration()

        # Apply to Kong
        await KongIntegrationService.update_plugin_config(default_config.dict())

        # Store configuration
        reset_config = await ConfigurationService.update_configuration(default_config)

        return ConfigurationResponse(
            status="success",
            message="Configuration reset to defaults",
            configuration=reset_config,
            timestamp=datetime.utcnow(),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to reset configuration: {str(e)}"
        )


@router.get("/history", response_model=dict[str, Any])
async def get_configuration_history(limit: int = 10, current_user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """
    Get configuration change history.

    Returns recent configuration changes with timestamps and user information.
    """
    try:
        history = await ConfigurationService.get_configuration_history(limit)

        return {"total": len(history), "history": history}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to retrieve history: {str(e)}"
        )
