/**
 * AI Service Configuration (OpenAI)
 */

const axios = require('axios');
const logger = require('../utils/logger');

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-3.5-turbo';
const OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions';

/**
 * Call OpenAI API for threat analysis
 */
async function analyzeThreatWithAI(description) {
    try {
        if (!OPENAI_API_KEY) {
            throw new Error('OpenAI API key not configured');
        }

        const prompt = `
You are a cybersecurity expert analyzing a hotel's incident report. 
Analyze the following incident description and provide a structured JSON response with:
1. threatType: The type of threat (e.g., Phishing, Malware, DDoS, Ransomware, Unauthorized Access, Data Breach)
2. threatCategory: The category (Social Engineering, Malicious Software, Network Attack, etc.)
3. affectedAsset: The most likely affected asset type
4. confidence: Confidence level (0-100)
5. likelihood: Estimated likelihood (1-4, where 4 is most likely)
6. impact: Estimated impact (1-4, where 4 is most severe)
7. mitigationSteps: Array of 3-5 actionable mitigation steps
8. nistFunctions: Array of relevant NIST functions (Identify, Protect, Detect, Respond, Recover)
9. nistControls: Array of relevant NIST controls (e.g., PR.AC, DE.CM, RS.RP)

Incident Description:
"${description}"

Respond ONLY with valid JSON, no other text.
`;

        const response = await axios.post(
            OPENAI_API_URL,
            {
                model: OPENAI_MODEL,
                messages: [
                    {
                        role: 'system',
                        content: 'You are a cybersecurity expert. Respond only with valid JSON.',
                    },
                    {
                        role: 'user',
                        content: prompt,
                    },
                ],
                temperature: 0.7,
                max_tokens: 500,
            },
            {
                headers: {
                    'Authorization': `Bearer ${OPENAI_API_KEY}`,
                    'Content-Type': 'application/json',
                },
            }
        );

        const content = response.data.choices[0].message.content;
        const analysis = JSON.parse(content);

        return analysis;

    } catch (error) {
        logger.error('AI Analysis Error:', error.message);
        throw new Error('Failed to analyze threat with AI');
    }
}

/**
 * Generate recommendations based on threat type
 */
async function generateRecommendations(threatType, threatDetails) {
    try {
        if (!OPENAI_API_KEY) {
            throw new Error('OpenAI API key not configured');
        }

        const prompt = `
You are a cybersecurity expert. Generate detailed, actionable recommendations for a small hotel to mitigate a ${threatType} threat.

Threat Details:
- Type: ${threatType}
- Category: ${threatDetails.threatCategory}
- Affected Asset: ${threatDetails.affectedAsset}

Provide 5-7 specific, practical recommendations that:
1. Are implementable by non-technical hotel staff
2. Consider budget constraints of small businesses
3. Are aligned with NIST Cybersecurity Framework
4. Include both immediate and long-term actions

Format as a JSON array of recommendation strings. Respond ONLY with valid JSON array, no other text.
`;

        const response = await axios.post(
            OPENAI_API_URL,
            {
                model: OPENAI_MODEL,
                messages: [
                    {
                        role: 'system',
                        content: 'You are a cybersecurity expert for small businesses. Respond only with valid JSON.',
                    },
                    {
                        role: 'user',
                        content: prompt,
                    },
                ],
                temperature: 0.7,
                max_tokens: 500,
            },
            {
                headers: {
                    'Authorization': `Bearer ${OPENAI_API_KEY}`,
                    'Content-Type': 'application/json',
                },
            }
        );

        const content = response.data.choices[0].message.content;
        const recommendations = JSON.parse(content);

        return recommendations;

    } catch (error) {
        logger.error('Recommendation Generation Error:', error.message);
        return [];
    }
}

module.exports = {
    analyzeThreatWithAI,
    generateRecommendations,
};