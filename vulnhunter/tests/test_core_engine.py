"""
Test Core Engine
===============

Tests for VulnHunter core engine functionality.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from pathlib import Path

from vulnhunter.core.engine import VulnHunterEngine
from vulnhunter.core.config import VulnHunterConfig


class TestVulnHunterEngine:
    """Test suite for VulnHunter core engine."""

    @pytest.fixture
    def mock_config(self):
        """Create mock configuration."""
        config = Mock(spec=VulnHunterConfig)
        config.models = {
            'source_code': Mock(),
            'http_requests': Mock(),
            'mobile_apps': Mock(),
            'executables': Mock(),
            'smart_contracts': Mock()
        }
        return config

    @pytest.fixture
    def mock_model_manager(self):
        """Create mock model manager."""
        manager = Mock()
        manager.load_all_models = AsyncMock(return_value={
            'source_code': True,
            'http_requests': True,
            'mobile_apps': True,
            'executables': True,
            'smart_contracts': True
        })
        manager.loaded_models = {
            'source_code': Mock(),
            'http_requests': Mock(),
            'mobile_apps': Mock(),
            'executables': Mock(),
            'smart_contracts': Mock()
        }
        return manager

    @pytest.fixture
    def mock_analyzers(self):
        """Create mock analyzers."""
        analyzers = {}
        for analyzer_name in ['source_code', 'http_requests', 'mobile_apps', 'executables', 'smart_contracts']:
            analyzer = Mock()
            analyzer.initialize = AsyncMock()
            analyzer.analyze = AsyncMock(return_value={
                'status': 'success',
                'vulnerability_detected': True,
                'confidence_score': 0.8,
                'risk_assessment': {'level': 'HIGH'}
            })
            analyzers[analyzer_name] = analyzer
        return analyzers

    @pytest.fixture
    async def engine(self, mock_config):
        """Create VulnHunter engine instance."""
        with patch('vulnhunter.core.engine.ModelManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.load_all_models = AsyncMock(return_value={})
            mock_manager_class.return_value = mock_manager

            with patch.multiple(
                'vulnhunter.core.engine',
                SourceCodeAnalyzer=Mock(),
                HTTPRequestAnalyzer=Mock(),
                MobileAppAnalyzer=Mock(),
                ExecutableAnalyzer=Mock(),
                SmartContractAnalyzer=Mock()
            ):
                engine = VulnHunterEngine(mock_config)
                return engine

    def test_engine_initialization(self, mock_config):
        """Test engine initialization."""
        with patch('vulnhunter.core.engine.ModelManager'):
            with patch.multiple(
                'vulnhunter.core.engine',
                SourceCodeAnalyzer=Mock(),
                HTTPRequestAnalyzer=Mock(),
                MobileAppAnalyzer=Mock(),
                ExecutableAnalyzer=Mock(),
                SmartContractAnalyzer=Mock()
            ):
                engine = VulnHunterEngine(mock_config)

                assert engine.config == mock_config
                assert not engine._initialized
                assert len(engine.analyzers) == 5

    @pytest.mark.asyncio
    async def test_engine_initialize_success(self, engine):
        """Test successful engine initialization."""
        # Mock model manager
        engine.model_manager.load_all_models = AsyncMock(return_value={
            'source_code': True,
            'http_requests': True
        })

        # Mock analyzers
        for analyzer in engine.analyzers.values():
            analyzer.initialize = AsyncMock()

        result = await engine.initialize()

        assert result is True
        assert engine._initialized is True
        engine.model_manager.load_all_models.assert_called_once()

    @pytest.mark.asyncio
    async def test_engine_initialize_failure(self, engine):
        """Test engine initialization failure."""
        engine.model_manager.load_all_models = AsyncMock(side_effect=Exception("Failed to load models"))

        result = await engine.initialize()

        assert result is False
        assert engine._initialized is False

    @pytest.mark.asyncio
    async def test_analyze_not_initialized(self, engine):
        """Test analysis when engine is not initialized."""
        with pytest.raises(RuntimeError, match="Engine not initialized"):
            await engine.analyze("test code")

    @pytest.mark.asyncio
    async def test_analyze_source_code(self, engine):
        """Test source code analysis."""
        engine._initialized = True

        # Mock analyzer
        mock_analyzer = Mock()
        mock_analyzer.analyze = AsyncMock(return_value={
            'status': 'success',
            'vulnerability_detected': True,
            'confidence_score': 0.85
        })
        engine.analyzers['source_code'] = mock_analyzer

        result = await engine.analyze("def test(): pass", "source_code")

        assert result['status'] != 'error'
        assert 'analysis_id' in result
        assert 'timestamp' in result
        assert 'analysis_type' in result
        mock_analyzer.analyze.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_auto_detection(self, engine):
        """Test automatic target type detection."""
        engine._initialized = True

        # Mock analyzer
        mock_analyzer = Mock()
        mock_analyzer.analyze = AsyncMock(return_value={'status': 'success'})
        engine.analyzers['source_code'] = mock_analyzer

        # Test Python code detection
        result = await engine.analyze("def function(): pass", "auto")

        assert result['analysis_type'] == 'source_code'

    @pytest.mark.asyncio
    async def test_analyze_invalid_type(self, engine):
        """Test analysis with invalid type."""
        engine._initialized = True

        result = await engine.analyze("test", "invalid_type")

        assert result['status'] == 'error'
        assert 'Unknown analysis type' in result['error']

    @pytest.mark.asyncio
    async def test_batch_analyze(self, engine):
        """Test batch analysis."""
        engine._initialized = True

        # Mock analyzer
        mock_analyzer = Mock()
        mock_analyzer.analyze = AsyncMock(return_value={
            'status': 'success',
            'vulnerability_detected': True
        })
        engine.analyzers['source_code'] = mock_analyzer

        targets = [
            {'target': 'code1', 'type': 'source_code'},
            {'target': 'code2', 'type': 'source_code'}
        ]

        results = await engine.batch_analyze(targets, max_concurrent=2)

        assert len(results) == 2
        assert all('analysis_id' in result for result in results)

    @pytest.mark.asyncio
    async def test_batch_analyze_with_exception(self, engine):
        """Test batch analysis with exceptions."""
        engine._initialized = True

        # Mock analyzer that raises exception
        mock_analyzer = Mock()
        mock_analyzer.analyze = AsyncMock(side_effect=Exception("Analysis failed"))
        engine.analyzers['source_code'] = mock_analyzer

        targets = [{'target': 'code1', 'type': 'source_code'}]

        results = await engine.batch_analyze(targets)

        assert len(results) == 1
        assert results[0]['status'] == 'error'

    def test_get_supported_types(self, engine):
        """Test getting supported analysis types."""
        types = engine.get_supported_types()

        expected_types = ['source_code', 'http_requests', 'mobile_apps', 'executables', 'smart_contracts']
        assert set(types) == set(expected_types)

    def test_get_model_info(self, engine):
        """Test getting model information."""
        engine.model_manager.get_model_info = Mock(return_value={
            'loaded_models': 5,
            'total_models': 5
        })

        info = engine.get_model_info()

        assert 'loaded_models' in info
        engine.model_manager.get_model_info.assert_called_once()

    def test_get_engine_stats(self, engine):
        """Test getting engine statistics."""
        engine.model_manager.loaded_models = {'source_code': Mock()}
        engine.model_manager.get_model_info = Mock(return_value={})

        stats = engine.get_engine_stats()

        assert stats['version'] == '2.0.0'
        assert stats['initialized'] == engine._initialized
        assert 'supported_types' in stats
        assert 'loaded_models' in stats

    def test_detect_target_type_python_file(self, engine):
        """Test target type detection for Python file."""
        target = Path("test.py")
        detected_type = engine._detect_target_type(target)
        assert detected_type == 'source_code'

    def test_detect_target_type_apk_file(self, engine):
        """Test target type detection for APK file."""
        target = Path("app.apk")
        detected_type = engine._detect_target_type(target)
        assert detected_type == 'mobile_apps'

    def test_detect_target_type_http_url(self, engine):
        """Test target type detection for HTTP URL."""
        target = "https://example.com/api"
        detected_type = engine._detect_target_type(target)
        assert detected_type == 'http_requests'

    def test_detect_target_type_smart_contract_address(self, engine):
        """Test target type detection for smart contract address."""
        target = "0x1234567890123456789012345678901234567890"
        detected_type = engine._detect_target_type(target)
        assert detected_type == 'smart_contracts'

    def test_detect_target_type_http_dict(self, engine):
        """Test target type detection for HTTP request dict."""
        target = {"method": "GET", "url": "https://example.com"}
        detected_type = engine._detect_target_type(target)
        assert detected_type == 'http_requests'

    def test_detect_target_type_default(self, engine):
        """Test target type detection default case."""
        target = "unknown content"
        detected_type = engine._detect_target_type(target)
        assert detected_type == 'source_code'  # Default

    def test_get_target_info_path(self, engine):
        """Test target info extraction for Path."""
        target = Path("test.py")
        info = engine._get_target_info(target)

        assert info['type'] == 'PosixPath' or info['type'] == 'WindowsPath'
        assert 'path' in info
        assert 'extension' in info

    def test_get_target_info_string(self, engine):
        """Test target info extraction for string."""
        target = "test string"
        info = engine._get_target_info(target)

        assert info['type'] == 'str'
        assert info['content_length'] == len(target)

    def test_get_target_info_bytes(self, engine):
        """Test target info extraction for bytes."""
        target = b"test bytes"
        info = engine._get_target_info(target)

        assert info['type'] == 'bytes'
        assert info['size'] == len(target)

    def test_get_target_info_dict(self, engine):
        """Test target info extraction for dict."""
        target = {"key": "value", "method": "GET"}
        info = engine._get_target_info(target)

        assert info['type'] == 'dict'
        assert set(info['keys']) == set(target.keys())