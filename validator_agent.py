"""
Validator Agent
Validates extracted document data and calculates quality/conformity scores
"""
import asyncio
from typing import Dict, Any, List, Tuple
from datetime import datetime
import re

from base_agent import BaseAgent
from a2a_protocol import ErrorCodes
from config import AGENTS_CONFIG


class ValidationRule:
    """Base class for validation rules"""
    
    def __init__(self, name: str, weight: float = 1.0):
        self.name = name
        self.weight = weight
    
    def validate(self, data: Dict[str, Any]) -> Tuple[bool, float, str]:
        """
        Validate data against rule
        Returns: (passed, score, message)
        """
        raise NotImplementedError


class DataCompletenessRule(ValidationRule):
    """Check if required fields are present and non-empty"""
    
    def __init__(self, required_fields: List[str], weight: float = 1.5):
        super().__init__("Data Completeness", weight)
        self.required_fields = required_fields
    
    def validate(self, data: Dict[str, Any]) -> Tuple[bool, float, str]:
        missing_fields = []
        empty_fields = []
        
        for field in self.required_fields:
            if field not in data:
                missing_fields.append(field)
            elif not data[field] or (isinstance(data[field], str) and not data[field].strip()):
                empty_fields.append(field)
        
        total_fields = len(self.required_fields)
        valid_fields = total_fields - len(missing_fields) - len(empty_fields)
        score = (valid_fields / total_fields) * 100 if total_fields > 0 else 0
        
        passed = len(missing_fields) == 0 and len(empty_fields) == 0
        
        message = "All required fields present and non-empty"
        if missing_fields:
            message = f"Missing fields: {', '.join(missing_fields)}"
        elif empty_fields:
            message = f"Empty fields: {', '.join(empty_fields)}"
        
        return passed, score, message


class DataFormatRule(ValidationRule):
    """Validate data format using regex patterns"""
    
    def __init__(self, field_patterns: Dict[str, str], weight: float = 1.0):
        super().__init__("Data Format", weight)
        self.field_patterns = field_patterns
    
    def validate(self, data: Dict[str, Any]) -> Tuple[bool, float, str]:
        invalid_fields = []
        
        for field, pattern in self.field_patterns.items():
            if field in data and data[field]:
                value = str(data[field])
                if not re.match(pattern, value):
                    invalid_fields.append(field)
        
        total_fields = len(self.field_patterns)
        valid_fields = total_fields - len(invalid_fields)
        score = (valid_fields / total_fields) * 100 if total_fields > 0 else 100
        
        passed = len(invalid_fields) == 0
        message = "All fields match expected format" if passed else f"Invalid format: {', '.join(invalid_fields)}"
        
        return passed, score, message


class DataQualityRule(ValidationRule):
    """Check data quality metrics"""
    
    def __init__(self, min_text_length: int = 10, weight: float = 1.0):
        super().__init__("Data Quality", weight)
        self.min_text_length = min_text_length
    
    def validate(self, data: Dict[str, Any]) -> Tuple[bool, float, str]:
        issues = []
        score = 100.0
        
        # Check text content length for PDFs
        if 'text_content' in data:
            text_length = len(data['text_content'].strip())
            if text_length < self.min_text_length:
                issues.append(f"Text too short ({text_length} chars)")
                score -= 30
        
        # Check for missing values in CSV data
        if 'missing_values' in data:
            total_missing = sum(data['missing_values'].values())
            if 'row_count' in data and data['row_count'] > 0:
                missing_percentage = (total_missing / (data['row_count'] * data.get('column_count', 1))) * 100
                if missing_percentage > 50:
                    issues.append(f"High missing data rate ({missing_percentage:.1f}%)")
                    score -= 40
                elif missing_percentage > 20:
                    issues.append(f"Moderate missing data rate ({missing_percentage:.1f}%)")
                    score -= 20
        
        # Check data volume
        if 'row_count' in data:
            if data['row_count'] == 0:
                issues.append("No data rows")
                score -= 50
            elif data['row_count'] < 5:
                issues.append("Very few data rows")
                score -= 20
        
        score = max(0, score)
        passed = len(issues) == 0
        message = "Data quality acceptable" if passed else "; ".join(issues)
        
        return passed, score, message


class DataConsistencyRule(ValidationRule):
    """Check data consistency"""
    
    def __init__(self, weight: float = 1.0):
        super().__init__("Data Consistency", weight)
    
    def validate(self, data: Dict[str, Any]) -> Tuple[bool, float, str]:
        issues = []
        score = 100.0
        
        # Check table consistency for PDFs
        if 'tables' in data:
            for table in data['tables']:
                if 'rows' in table and 'column_count' in table:
                    # Check if all rows have same number of columns
                    inconsistent_rows = 0
                    for row in table['rows']:
                        if len(row) != table['column_count']:
                            inconsistent_rows += 1
                    
                    if inconsistent_rows > 0:
                        issues.append(f"Table has {inconsistent_rows} inconsistent rows")
                        score -= 15
        
        # Check column type consistency for CSV
        if 'data' in data and 'columns' in data:
            # Sample check: ensure numeric columns don't have too many non-numeric values
            if isinstance(data['data'], list) and len(data['data']) > 0:
                for col in data.get('columns', []):
                    if 'summary_statistics' in data and col in data['summary_statistics']:
                        # This is a numeric column, check consistency
                        numeric_count = sum(1 for row in data['data'] if col in row and isinstance(row[col], (int, float)))
                        total_count = len(data['data'])
                        if numeric_count < total_count * 0.8:  # Less than 80% numeric
                            issues.append(f"Column '{col}' has inconsistent types")
                            score -= 10
        
        score = max(0, score)
        passed = len(issues) == 0
        message = "Data is consistent" if passed else "; ".join(issues)
        
        return passed, score, message


class ValidatorAgent(BaseAgent):
    """
    Validator agent that applies quality rules and calculates conformity scores
    """
    
    def __init__(self):
        config = AGENTS_CONFIG['validator']
        super().__init__('Validator', config['host'], config['port'])
        
        self.validation_rules = self._initialize_rules()
    
    def _register_handlers(self):
        """Register message handlers"""
        self.protocol.register_handler('validate_document', self.handle_validate_document)
        self.protocol.register_handler('get_validation_rules', self.handle_get_validation_rules)
    
    async def initialize(self):
        """Initialize validator"""
        self.logger.info("Validator initialized")
    
    async def cleanup(self):
        """Cleanup resources"""
        self.logger.info("Validator cleanup completed")
    
    def _initialize_rules(self) -> Dict[str, List[ValidationRule]]:
        """Initialize validation rules for different document types"""
        return {
            'pdf': [
                DataCompletenessRule(['text_content', 'total_pages'], weight=1.5),
                DataQualityRule(min_text_length=50, weight=1.2),
                DataConsistencyRule(weight=1.0)
            ],
            'csv': [
                DataCompletenessRule(['columns', 'data', 'row_count'], weight=1.5),
                DataQualityRule(min_text_length=0, weight=1.2),
                DataConsistencyRule(weight=1.3)
            ],
            'generic': [
                DataQualityRule(weight=1.0)
            ]
        }
    
    async def handle_validate_document(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate extracted document data
        Params: {
            "s3_key": "path/to/document",
            "extracted_data": {...},
            "document_type": "pdf|csv"
        }
        """
        s3_key = params.get('s3_key')
        extracted_data = params.get('extracted_data')
        document_type = params.get('document_type', 'generic')
        
        if not extracted_data:
            raise ValueError("Missing required parameter: extracted_data")
        
        self.logger.info(f"Validating document: {s3_key} (type: {document_type})")
        
        # Get appropriate validation rules
        rules = self.validation_rules.get(document_type, self.validation_rules['generic'])
        
        # Run all validation rules
        validation_results = []
        total_weight = sum(rule.weight for rule in rules)
        weighted_score = 0.0
        all_passed = True
        
        for rule in rules:
            try:
                passed, score, message = rule.validate(extracted_data)
                
                validation_results.append({
                    'rule': rule.name,
                    'passed': passed,
                    'score': score,
                    'weight': rule.weight,
                    'message': message
                })
                
                weighted_score += (score * rule.weight)
                
                if not passed:
                    all_passed = False
                
                self.logger.debug(f"Rule '{rule.name}': passed={passed}, score={score:.2f}")
                
            except Exception as e:
                self.logger.error(f"Error running rule '{rule.name}': {str(e)}")
                validation_results.append({
                    'rule': rule.name,
                    'passed': False,
                    'score': 0.0,
                    'weight': rule.weight,
                    'message': f"Validation error: {str(e)}"
                })
                all_passed = False
        
        # Calculate final score
        final_score = weighted_score / total_weight if total_weight > 0 else 0.0
        
        # Determine validation status
        if final_score >= 90:
            status = 'excellent'
        elif final_score >= 75:
            status = 'good'
        elif final_score >= 60:
            status = 'acceptable'
        elif final_score >= 40:
            status = 'poor'
        else:
            status = 'failed'
        
        result = {
            's3_key': s3_key,
            'document_type': document_type,
            'score': round(final_score, 2),
            'status': status,
            'all_rules_passed': all_passed,
            'validation_timestamp': datetime.now().isoformat(),
            'details': {
                'rules_evaluated': len(validation_results),
                'rules_passed': sum(1 for r in validation_results if r['passed']),
                'rules_failed': sum(1 for r in validation_results if not r['passed']),
                'results': validation_results
            }
        }
        
        self.logger.info(f"Validation completed: {s3_key}, score={final_score:.2f}, status={status}")
        return result
    
    async def handle_get_validation_rules(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get list of validation rules"""
        document_type = params.get('document_type', 'all')
        
        if document_type == 'all':
            rules_info = {}
            for doc_type, rules in self.validation_rules.items():
                rules_info[doc_type] = [
                    {'name': rule.name, 'weight': rule.weight}
                    for rule in rules
                ]
            return {'rules': rules_info}
        else:
            rules = self.validation_rules.get(document_type, [])
            return {
                'document_type': document_type,
                'rules': [
                    {'name': rule.name, 'weight': rule.weight}
                    for rule in rules
                ]
            }
    
    async def _get_agent_status(self) -> Dict[str, Any]:
        """Get validator status"""
        status = await super()._get_agent_status()
        status.update({
            'supported_document_types': list(self.validation_rules.keys()),
            'total_rules': sum(len(rules) for rules in self.validation_rules.values())
        })
        return status


async def main():
    """Run the Validator agent"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    agent = ValidatorAgent()
    await agent.run()


if __name__ == '__main__':
    asyncio.run(main())

