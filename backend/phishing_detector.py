"""
Simple ML-based Phishing URL Detector
Uses RandomForest Classifier with URL features
"""

import pickle
import os
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np

class PhishingDetector:
    def __init__(self, model_path='phishing_model.pkl', scaler_path='scaler.pkl'):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = None
        self.feature_names = ['url_length', 'num_dots', 'num_special_chars', 
                             'has_https', 'num_hyphens', 'num_digits',
                             'subdomain_count', 'path_length', 'num_slashes']
        
        self.load_or_train_model()
    
    def extract_features(self, url):
        """Extract features from a URL"""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = url.lower()
            
            features = {
                'url_length': len(url),
                'num_dots': url.count('.'),
                'num_special_chars': sum(1 for c in url if c in '!@#$%^&*()_+-=[]{}|;:,.<>?'),
                'has_https': 1 if parsed.scheme == 'https' else 0,
                'num_hyphens': url.count('-'),
                'num_digits': sum(1 for c in url if c.isdigit()),
                'subdomain_count': hostname.count('.'),
                'path_length': len(path),
                'num_slashes': url.count('/'),
            }
            
            return [features[key] for key in self.feature_names]
        except Exception as e:
            print(f"Error extracting features: {e}")
            return None
    
    def train_model(self):
        """Train the phishing detector model with sample data"""
        # Training data: phishing and legitimate URLs
        phishing_urls = [
            'http://192.168.1.1/admin',
            'http://example-login.com/verify',
            'http://secure-paypal.com/account/update',
            'http://mail.google.com.suspicious.ru/login',
            'http://bit.ly/verify-account',
            'http://199.100.200.150/bank',
            'http://example.com@suspicious.com/login',
            'http://example%20com/verify',
            'http://example.com/login?redirect=bank.com',
            'http://faebook.com/login',
            'http://www-amazon.com/account',
            'http://update-apple.com/signin',
            'http://confirm-identity.com/verify',
            'http://reset-password-now.com',
        ]
        
        legitimate_urls = [
            'https://github.com/login',
            'https://www.google.com',
            'https://stackoverflow.com/questions',
            'https://www.wikipedia.org/wiki/Main_Page',
            'https://www.youtube.com/watch',
            'https://twitter.com/search',
            'https://www.facebook.com/feed',
            'https://www.linkedin.com/feed',
            'https://mail.google.com/mail',
            'https://www.amazon.com/s',
            'https://www.github.com/explore',
            'https://www.netflix.com/browse',
            'https://www.dropbox.com/home',
            'https://www.slack.com/workspace',
        ]
        
        # Extract features
        X = []
        y = []
        
        for url in phishing_urls:
            features = self.extract_features(url)
            if features:
                X.append(features)
                y.append(1)  # 1 = phishing
        
        for url in legitimate_urls:
            features = self.extract_features(url)
            if features:
                X.append(features)
                y.append(0)  # 0 = legitimate
        
        X = np.array(X)
        y = np.array(y)
        
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=2,
            min_samples_leaf=1,
            random_state=42,
            class_weight='balanced'
        )
        self.model.fit(X_scaled, y)
        
        # Save model
        self.save_model()
    
    def save_model(self):
        """Save the trained model to disk"""
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
        except Exception as e:
            print(f"Error saving model: {e}")
    
    def load_model(self):
        """Load the trained model from disk"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                return True
        except Exception as e:
            print(f"Error loading model: {e}")
        return False
    
    def load_or_train_model(self):
        """Load existing model or train a new one"""
        if not self.load_model():
            self.train_model()
    
    def predict(self, url):
        """
        Predict if a URL is phishing or legitimate
        Returns: {
            'is_phishing': bool,
            'confidence': float (0-100),
            'risk_score': int (0-100),
            'reasons': list of strings
        }
        """
        try:
            features = self.extract_features(url)
            if features is None:
                return {
                    'is_phishing': True,
                    'confidence': 95,
                    'risk_score': 95,
                    'reasons': ['Invalid URL format detected']
                }
            
            features_array = np.array([features])
            features_scaled = self.scaler.transform(features_array)
            
            # Get prediction and probability
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            # Extract individual features for analysis
            parsed = urlparse(url)
            feature_dict = dict(zip(self.feature_names, features))
            
            # Generate reasons
            reasons = []
            
            if feature_dict['url_length'] > 75:
                reasons.append('URL is unusually long (potential masking)')
            elif feature_dict['url_length'] > 50:
                reasons.append('URL length is above average')
            
            if feature_dict['num_dots'] > 5:
                reasons.append('Excessive number of dots in URL')
            
            if feature_dict['num_special_chars'] > 3:
                reasons.append('Multiple special characters detected')
            
            if feature_dict['has_https'] == 0:
                reasons.append('Missing HTTPS protocol')
            
            if feature_dict['num_hyphens'] > 2:
                reasons.append('Multiple hyphens in domain (common in phishing)')
            
            if feature_dict['subdomain_count'] > 2:
                reasons.append('Suspicious number of subdomains')
            
            if '@' in url:
                reasons.append('URL contains "@" symbol (user info indicator)')
            
            # Calculate confidence and risk score
            max_prob = float(max(probabilities))
            confidence = max_prob * 100
            
            # Risk score (0-100)
            if prediction == 1:  # Phishing
                risk_score = int(max_prob * 100)
            else:  # Legitimate
                risk_score = int((1 - max_prob) * 100)
            
            return {
                'is_phishing': prediction == 1,
                'confidence': round(confidence, 1),
                'risk_score': risk_score,
                'reasons': reasons if reasons else ['No major red flags detected']
            }
        
        except Exception as e:
            print(f"Error during prediction: {e}")
            return {
                'is_phishing': True,
                'confidence': 50,
                'risk_score': 50,
                'reasons': [f'Error analyzing URL: {str(e)}']
            }


# Global detector instance
detector = None

def get_detector():
    """Get or create the global detector instance"""
    global detector
    if detector is None:
        detector = PhishingDetector(
            model_path=os.path.join(os.path.dirname(__file__), 'phishing_model.pkl'),
            scaler_path=os.path.join(os.path.dirname(__file__), 'scaler.pkl')
        )
    return detector

def analyze_url_ml(url):
    """Simple interface to analyze a URL using ML"""
    detector = get_detector()
    result = detector.predict(url)
    
    return {
        'status': 'Phishing' if result['is_phishing'] else 'Safe',
        'risk_score': result['risk_score'],
        'reasons': result['reasons']
    }
