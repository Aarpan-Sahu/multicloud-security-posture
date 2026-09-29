from .base import BaseCollector

__all__ = ["BaseCollector", "get_collector"]


def get_collector(provider: str, **kwargs) -> BaseCollector:
    """Lazy import so users only need the SDK for the clouds they actually scan."""
    if provider == "aws":
        from .aws import AWSCollector
        return AWSCollector(**kwargs)
    if provider == "azure":
        from .azure import AzureCollector
        return AzureCollector(**kwargs)
    if provider == "gcp":
        from .gcp import GCPCollector
        return GCPCollector(**kwargs)
    if provider == "demo":
        from .demo import DemoCollector
        return DemoCollector(**kwargs)
    raise ValueError(f"Unknown provider: {provider}")
