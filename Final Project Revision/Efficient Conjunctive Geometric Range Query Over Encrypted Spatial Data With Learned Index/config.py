"""Config for ECGRQ-LI Test Suite"""

MONGO_URI = "mongodb+srv://yewza232_db_user:5qCbuPzMrzPSpflq@projectsomchart.lkihxz4.mongodb.net/?appName=ProjectSomchart"
DB_NAME = "ecgrq_li_test"
COL_SPATIAL = "spatial_data"
COL_INDEX = "encrypted_index"
COL_RESULTS = "experiment_results"
COL_MODELS = "learned_index_models"

DATASET_SIZES = [200_000, 400_000, 600_000, 800_000, 1_000_000]
ATTRIBUTE_SIZES = [2, 3, 4, 5, 6]
EPSILON_VALUES = [0.2, 0.4, 0.6, 0.8, 1.0]
QUERY_REGION = 64
NUM_ATTRS = 3
TRAINING_ROUNDS = 50
HIDDEN_NEURONS = 128
LR = 0.0001
BATCH_SIZE = 1000

LAT_MIN, LAT_MAX = 39.0, 41.0
LON_MIN, LON_MAX = 115.0, 117.5
Z_BITS = 16
OUTPUT_DIR = "experiment_results"
