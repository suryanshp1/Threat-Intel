-- Add taxonomy entity kinds without rewriting or removing existing intelligence.
ALTER TABLE intelligence_entities DROP CONSTRAINT IF EXISTS intelligence_entities_kind_check;
ALTER TABLE intelligence_entities ADD CONSTRAINT intelligence_entities_kind_check
 CHECK(kind IN ('actors','ransomware','patches','rules','relationships','products','weaknesses','categories'));
