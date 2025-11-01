#!/usr/bin/env python3
"""
Plugin Management System for VulnHunter Professional
"""

import os
import sys
import importlib
import inspect
from typing import Dict, List, Any, Type, Optional, Protocol
from pathlib import Path
import logging
from abc import ABC, abstractmethod

from .vulnerability import Vulnerability
from .analysis_result import AnalysisResult


class AnalysisPlugin(Protocol):
    """Protocol for analysis plugins"""

    name: str
    version: str
    supported_file_types: List[str]

    def analyze(self, file_path: str, content: str, context: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze file content and return discovered vulnerabilities"""
        ...

    def is_applicable(self, file_path: str, content: str) -> bool:
        """Check if plugin is applicable to the given file"""
        ...


class BasePlugin(ABC):
    """Base class for all VulnHunter plugins"""

    def __init__(self):
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.logger = logging.getLogger(f"vulnhunter.plugin.{self.name}")

    @abstractmethod
    def analyze(self, file_path: str, content: str, context: Dict[str, Any]) -> List[Vulnerability]:
        """Main analysis method - must be implemented by all plugins"""
        pass

    @abstractmethod
    def is_applicable(self, file_path: str, content: str) -> bool:
        """Check if this plugin should analyze the given file"""
        pass

    @property
    @abstractmethod
    def supported_file_types(self) -> List[str]:
        """List of supported file extensions"""
        pass

    def get_config(self) -> Dict[str, Any]:
        """Get plugin configuration"""
        return {}

    def set_config(self, config: Dict[str, Any]) -> None:
        """Set plugin configuration"""
        pass


class PluginManager:
    """Manages loading and execution of analysis plugins"""

    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        self.logger = logging.getLogger(__name__)
        self.plugins: Dict[str, BasePlugin] = {}
        self.plugin_dirs = plugin_dirs or []
        self._load_plugins()

    def _load_plugins(self) -> None:
        """Load all plugins from specified directories"""
        # Default plugin directories
        current_dir = Path(__file__).parent.parent
        default_dirs = [
            current_dir / "plugins" / "lang",
            current_dir / "plugins" / "analysis",
            current_dir / "plugins" / "exploit",
            current_dir / "plugins" / "output"
        ]

        all_dirs = [Path(d) for d in self.plugin_dirs] + default_dirs

        for plugin_dir in all_dirs:
            if plugin_dir.exists():
                self._load_plugins_from_directory(plugin_dir)

    def _load_plugins_from_directory(self, plugin_dir: Path) -> None:
        """Load plugins from a specific directory"""
        self.logger.info(f"Loading plugins from {plugin_dir}")

        # Add plugin directory to Python path
        if str(plugin_dir) not in sys.path:
            sys.path.insert(0, str(plugin_dir))

        # Find all Python files in the directory
        for plugin_file in plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("__"):
                continue

            try:
                self._load_plugin_file(plugin_file)
            except Exception as e:
                self.logger.error(f"Failed to load plugin {plugin_file}: {e}")

    def _load_plugin_file(self, plugin_file: Path) -> None:
        """Load a single plugin file"""
        module_name = plugin_file.stem

        try:
            # Import the module
            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            if spec is None:
                raise ImportError(f"Could not load spec for {plugin_file}")

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find plugin classes
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, BasePlugin) and
                    obj != BasePlugin and
                    not inspect.isabstract(obj)):

                    # Instantiate the plugin
                    plugin_instance = obj()
                    self.plugins[plugin_instance.name] = plugin_instance
                    self.logger.info(f"Loaded plugin: {plugin_instance.name}")

        except Exception as e:
            self.logger.error(f"Error loading plugin from {plugin_file}: {e}")

    def get_applicable_plugins(self, file_path: str, content: str) -> List[BasePlugin]:
        """Get list of plugins applicable to the given file"""
        applicable_plugins = []

        for plugin in self.plugins.values():
            try:
                if plugin.is_applicable(file_path, content):
                    applicable_plugins.append(plugin)
            except Exception as e:
                self.logger.error(f"Error checking applicability for plugin {plugin.name}: {e}")

        return applicable_plugins

    def analyze_with_plugins(self, file_path: str, content: str,
                           context: Optional[Dict[str, Any]] = None) -> List[Vulnerability]:
        """Analyze file with all applicable plugins"""
        if context is None:
            context = {}

        vulnerabilities = []
        applicable_plugins = self.get_applicable_plugins(file_path, content)

        self.logger.info(f"Analyzing {file_path} with {len(applicable_plugins)} plugins")

        for plugin in applicable_plugins:
            try:
                plugin_vulns = plugin.analyze(file_path, content, context)
                vulnerabilities.extend(plugin_vulns)
                self.logger.debug(f"Plugin {plugin.name} found {len(plugin_vulns)} vulnerabilities")
            except Exception as e:
                self.logger.error(f"Error in plugin {plugin.name}: {e}")

        return vulnerabilities

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get plugin by name"""
        return self.plugins.get(name)

    def list_plugins(self) -> List[str]:
        """List all loaded plugin names"""
        return list(self.plugins.keys())

    def get_plugin_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all loaded plugins"""
        info = {}
        for name, plugin in self.plugins.items():
            info[name] = {
                'name': plugin.name,
                'version': plugin.version,
                'supported_file_types': plugin.supported_file_types,
                'class': plugin.__class__.__name__
            }
        return info

    def reload_plugins(self) -> None:
        """Reload all plugins"""
        self.plugins.clear()
        self._load_plugins()

    def enable_plugin(self, name: str) -> bool:
        """Enable a specific plugin"""
        # Implementation for enabling/disabling plugins
        return True

    def disable_plugin(self, name: str) -> bool:
        """Disable a specific plugin"""
        # Implementation for enabling/disabling plugins
        return True