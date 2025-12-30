# Realtime-IDS

A comprehensive Real-time Intrusion Detection System (IDS) built with Python. This system combines machine learning-based anomaly detection with signature-based and heuristic-based detection rules to identify suspicious network traffic and potential security threats in real-time.

## Features

- **Packet Capture & Analysis**: Captures network packets using Scapy and extracts relevant network features
- **Multi-Detection Engine**: 
  - **Signature-Based Detection**: Uses predefined rules to identify known attack patterns
  - **Heuristic-Based Detection**: Applies heuristic rules for behavioral analysis
  - **Machine Learning Detection**: Employs Isolation Forest algorithm for anomaly detection
- **Real-time Traffic Monitoring**: Processes packets in real-time with low latency
- **Alert System**: Generates and logs alerts when suspicious activity is detected
- **Dashboard**: Web-based dashboard for monitoring and visualization
- **Database Logging**: Stores alerts and events in a persistent database
- **Model Training**: Supports model training for improved detection accuracy

## Project Structure

```
realtime-ids/
├── ids/                          # Core IDS implementation
│   ├── __init__.py
│   ├── main.py                   # Entry point
│   ├── engine.py                 # Detection engine with ML support
│   ├── capture.py                # Packet capture and processing
│   ├── analyzer.py               # Traffic analyzer
│   ├── alert.py                  # Alert system
│   ├── dashboard.py              # Web dashboard
│   ├── database.py               # Database operations
│   ├── utils.py                  # Utility functions
│   ├── api/                      # API endpoints
│   └── rules/                    # Detection rules
│       ├── signatures.py         # Signature-based rules
│       └── heuristics.py         # Heuristic rules
├── models/                       # ML models
│   ├── if_model.joblib           # Trained Isolation Forest model
│   └── scaler.joblib             # Feature scaler
├── scripts/                      # Utility scripts
│   └── train_model.py            # Model training script
├── tests/                        # Test suite
├── data/                         # Data files and logs
├── requirements.txt              # Project dependencies
├── run_ids.sh                    # Run IDS script
├── run_dashboard.sh              # Run dashboard script
└── README.md                     # This file
```

## Installation

### Prerequisites

- Python 3.8+
- pip (Python package manager)
- Linux/macOS (for packet capture with Scapy)

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/Roshita598/realtime-ids.git
   cd realtime-ids
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**
   ```bash
   python -m ids --help
   ```

## Dependencies

The project uses the following key dependencies:

- **scapy**: Packet capture and network analysis
- **scikit-learn**: Machine learning algorithms (Isolation Forest, StandardScaler)
- **numpy**: Numerical computations
- **pandas**: Data handling and analysis
- **flask8**: Code quality checking
- **pytest**: Unit testing framework
- **joblib**: Model serialization
- **streamlit**: Interactive web dashboard
- **matplotlib**: Data visualization

See `requirements.txt` for the complete list with versions.

## Quick Start

### Run the IDS

```bash
# Run with default interface
python -m ids --iface eth0

# Run with specific interface and filter
python -m ids --iface eth0
```

### Run the Dashboard

```bash
bash run_dashboard.sh
```

This starts the web dashboard on `http://localhost:8501`

## How It Works

### Detection Pipeline

1. **Packet Capture**: Packets are captured from the network interface using Scapy
2. **Feature Extraction**: Relevant network features are extracted from packets:
   - Packet size
   - Flow duration
   - Packet rate
   - Byte rate
   - TCP flags
   - Window size
3. **Detection Analysis**:
   - Signature rules check for known attack patterns
   - Heuristic rules evaluate behavioral indicators
   - ML model analyzes extracted features for anomalies
4. **Alert Generation**: When threats are detected, alerts are generated and logged
5. **Persistence**: Alerts are stored in the database for historical analysis

### Detection Engine

The `DetectionEngine` class implements:

- **Signature-based detection**: Pattern matching against known attack signatures
- **Heuristic detection**: Behavioral rule-based analysis
- **Anomaly detection**: Isolation Forest ML model for zero-day detection

### ML Model Training

Train the ML model with network traffic data:

```bash
python scripts/train_model.py
```

The model learns from normal traffic patterns and identifies deviations as potential threats.

## Configuration

### Network Interface

Specify the network interface to monitor:

```bash
python -m ids --iface <interface_name>
```

### Detection Rules

Modify signature and heuristic rules in:
- `ids/rules/signatures.py` - Add/modify signature rules
- `ids/rules/heuristics.py` - Add/modify heuristic rules

## Testing

Run the test suite:

```bash
pytest tests/
```

View test results and logs in the test output.

## Usage Examples

### Example 1: Basic IDS Monitoring

```bash
python -m ids --iface eth0
```

This starts real-time monitoring on `eth0` interface.

### Example 2: Dashboard Visualization

```bash
bash run_dashboard.sh
```

Access the dashboard at `http://localhost:8501` to view:
- Real-time alerts
- Traffic statistics
- Attack patterns
- Historical data

## Output and Logging

- **Console Output**: Real-time alerts are printed to console
- **Log Files**: Detailed logs stored in `data/` directory
- **Database**: Alert history stored in the system database
- **Dashboard**: Visual representation of threats and patterns

## Performance Considerations

- Designed for real-time packet processing
- Efficient feature extraction and analysis
- Scalable ML model for high-traffic environments
- Low latency detection pipeline

## Future Enhancements

- Deep learning-based detection models
- Distributed monitoring across multiple interfaces
- Advanced visualization and correlation analysis
- Integration with SIEM systems
- Custom rule builder interface
- Performance optimization for high-speed networks

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is available under the MIT License. See LICENSE file for details.

## Disclaimer

This IDS is provided for educational and authorized security testing purposes only. Ensure you have proper authorization before deploying this system on any network.

## Support & Contact

For issues, questions, or suggestions, please open an issue on the GitHub repository.

---

**Last Updated**: December 2025
