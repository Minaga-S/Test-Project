# Hotel Cybersecurity Governance System

AI-Assisted Cybersecurity Threat Assessment and Governance System for Small Hotels

## Project Overview

This system assists small hotels in identifying and managing cybersecurity threats through an AI-powered platform that:

- Registers digital assets (POS systems, servers, networks, databases, devices)
- Reports and analyzes cyber incidents using natural language
- Assesses cybersecurity risks with automated scoring
- Maps threats to NIST Cybersecurity Framework controls
- Provides actionable mitigation recommendations

## Features

### For End Users (Non-Technical Staff)
- Simple incident reporting interface
- No technical jargon required
- Immediate risk assessment
- Clear recommendations

### For Security Managers
- Asset inventory management
- Comprehensive incident tracking
- Risk analysis dashboards
- NIST framework compliance mapping
- Trend analysis and reporting

### AI-Powered
- Natural language threat analysis
- Automated risk calculation
- Smart recommendations generation

## Technology Stack

### Frontend
- HTML5, CSS3, JavaScript (Vanilla)
- Chart.js for data visualization
- No external framework dependencies for simplicity

### Backend
- Node.js + Express.js
- MongoDB for data persistence
- OpenAI API for threat analysis
- JWT for authentication

### Security
- bcryptjs for password hashing
- JWT token authentication
- Input validation and sanitization
- CORS protection
- Helmet.js for HTTP headers

## Installation

### Prerequisites
- Node.js (v16 or higher)
- MongoDB (local or Atlas)
- OpenAI API key

### Backend Setup

```bash
cd backend
npm install