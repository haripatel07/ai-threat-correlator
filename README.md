# AI Threat Correlator

An intelligent cybersecurity tool that uses machine learning to correlate threat intelligence feeds with server logs, prioritizing and scoring potential security threats.

## Features

- **AI-Powered Threat Scoring**: Uses a trained Random Forest model to assess threat severity
- **Automated Feed Updates**: Downloads and processes threat intelligence from FireHOL blocklists
- **Log Analysis**: Parses web server logs to extract visitor IP addresses
- **Real-time Correlation**: Matches visitor IPs against known malicious IP databases
- **Prioritized Alerts**: Ranks threats by severity and provides actionable intelligence

## Installation

1. Clone the repository:
```bash
git clone https://github.com/haripatel07/ai-threat-correlator.git
cd ai-threat-correlator
```

2. Create a virtual environment:
```bash
python -m venv venv
venv\Scripts\activate  # On Windows
# or
source venv/bin/activate  # On Unix/Mac
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Training the Model

First, generate the training dataset and train the AI model:

```bash
python src/model/generate_dataset.py
python src/model/train_model.py
```

### Running Threat Correlation

Execute the main application to perform threat intelligence correlation:

```bash
python main.py
```

The application will:
1. Load the trained AI model
2. Download the latest threat feeds
3. Parse your server logs
4. Correlate visitor IPs with threat intelligence
5. Score and prioritize any detected threats

## Project Structure

```
ai-threat-correlator/
├── main.py                 # Main application entry point
├── requirements.txt        # Python dependencies
├── data/                   # Data directory
│   ├── firehol_level1.netset    # Downloaded threat feed
│   ├── sample_nginx.log         # Sample server log
│   └── training_data.csv        # Synthetic training data
├── models/                 # Trained ML models
│   ├── threat_scorer.joblib     # Trained Random Forest model
│   └── feature_columns.joblib   # Model feature columns
└── src/
    ├── collector/          # Data collection modules
    │   ├── feed_downloader.py   # Downloads threat feeds
    │   └── log_parser.py        # Parses server logs
    └── model/              # ML model components
        ├── generate_dataset.py  # Creates training data
        └── train_model.py       # Trains the AI model
```

## How It Works

1. **Data Generation**: Creates synthetic threat data with features like reputation scores, recency, threat types, and confidence levels
2. **Model Training**: Trains a Random Forest classifier to predict threat severity (Critical, High, Medium, Low)
3. **Feed Collection**: Downloads current threat intelligence feeds from reliable sources
4. **Log Parsing**: Extracts IP addresses from web server access logs
5. **Correlation**: Matches visitor IPs against known malicious IP databases
6. **AI Scoring**: Uses the trained model to assess threat severity and provide prioritized alerts

## Configuration

The application uses the following default paths:
- Threat feed: `data/firehol_level1.netset`
- Server log: `data/sample_nginx.log`
- Model files: `models/threat_scorer.joblib` and `models/feature_columns.joblib`

Modify the paths in `main.py` to use your own data sources.

## Dependencies

- pandas: Data manipulation and analysis
- scikit-learn: Machine learning algorithms
- joblib: Model serialization
- requests: HTTP requests for feed downloads

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is for educational and research purposes. Always verify threat intelligence from multiple sources and follow your organization's security policies.