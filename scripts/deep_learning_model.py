import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models, callbacks
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Tuple, Dict, List
import logging
import json
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DeepIDSModel:
    """
    Deep Learning model for Network Intrusion Detection System.
    Implements various architectures including DNN, CNN, LSTM, and Autoencoder.
    """

    def __init__(self, input_dim: int, model_type: str = 'dnn'):
        self.input_dim = input_dim
        self.model_type = model_type.lower()
        self.model = None
        self.history = None
        self.is_trained = False

        # Set random seeds for reproducibility
        tf.random.set_seed(42)
        np.random.seed(42)

    def build_dnn_model(self, hidden_layers: List[int] = [256, 128, 64, 32]) -> keras.Model:
        """Build Deep Neural Network model"""
        logger.info(f"Building DNN model with layers: {hidden_layers}")

        model = models.Sequential([
            layers.Input(shape=(self.input_dim,)),
            layers.BatchNormalization(),
        ])

        # Add hidden layers with dropout and batch normalization
        for i, units in enumerate(hidden_layers):
            model.add(layers.Dense(units, activation='relu', name=f'dense_{i + 1}'))
            model.add(layers.BatchNormalization())
            model.add(layers.Dropout(0.3))

        # Output layer
        model.add(layers.Dense(1, activation='sigmoid', name='output'))

        return model

    def build_cnn_model(self, filters: List[int] = [64, 32, 16]) -> keras.Model:
        """Build CNN model for network traffic (reshape features as 1D sequence)"""
        logger.info(f"Building CNN model with filters: {filters}")

        # Calculate reshape dimensions
        seq_length = int(np.sqrt(self.input_dim)) if int(
            np.sqrt(self.input_dim)) ** 2 == self.input_dim else self.input_dim

        model = models.Sequential([
            layers.Input(shape=(self.input_dim,)),
            layers.Reshape((seq_length, -1)),
            layers.BatchNormalization(),
        ])

        # Add convolutional layers
        for i, filter_size in enumerate(filters):
            model.add(layers.Conv1D(filter_size, 3, activation='relu', padding='same', name=f'conv1d_{i + 1}'))
            model.add(layers.BatchNormalization())
            model.add(layers.MaxPooling1D(2, padding='same'))
            model.add(layers.Dropout(0.3))

        # Flatten and add dense layers
        model.add(layers.GlobalAveragePooling1D())
        model.add(layers.Dense(64, activation='relu'))
        model.add(layers.Dropout(0.5))
        model.add(layers.Dense(1, activation='sigmoid', name='output'))

        return model

    def build_lstm_model(self, lstm_units: List[int] = [128, 64]) -> keras.Model:
        """Build LSTM model for sequential network traffic analysis"""
        logger.info(f"Building LSTM model with units: {lstm_units}")

        # Reshape input for LSTM (samples, timesteps, features)
        timesteps = min(10, self.input_dim)  # Use 10 timesteps or input_dim if smaller
        features = self.input_dim // timesteps

        model = models.Sequential([
            layers.Input(shape=(self.input_dim,)),
            layers.Reshape((timesteps, features)),
            layers.BatchNormalization(),
        ])

        # Add LSTM layers
        for i, units in enumerate(lstm_units):
            return_sequences = i < len(lstm_units) - 1
            model.add(layers.LSTM(units, return_sequences=return_sequences,
                                  dropout=0.3, recurrent_dropout=0.3, name=f'lstm_{i + 1}'))
            model.add(layers.BatchNormalization())

        # Dense layers
        model.add(layers.Dense(32, activation='relu'))
        model.add(layers.Dropout(0.5))
        model.add(layers.Dense(1, activation='sigmoid', name='output'))

        return model

    def build_autoencoder_model(self, encoding_dim: int = 32) -> Tuple[keras.Model, keras.Model]:
        """Build Autoencoder model for anomaly detection"""
        logger.info(f"Building Autoencoder model with encoding dimension: {encoding_dim}")

        # Encoder
        input_layer = layers.Input(shape=(self.input_dim,))
        encoded = layers.Dense(128, activation='relu')(input_layer)
        encoded = layers.BatchNormalization()(encoded)
        encoded = layers.Dropout(0.3)(encoded)
        encoded = layers.Dense(64, activation='relu')(encoded)
        encoded = layers.BatchNormalization()(encoded)
        encoded = layers.Dense(encoding_dim, activation='relu', name='encoded')(encoded)

        # Decoder
        decoded = layers.Dense(64, activation='relu')(encoded)
        decoded = layers.BatchNormalization()(decoded)
        decoded = layers.Dropout(0.3)(decoded)
        decoded = layers.Dense(128, activation='relu')(decoded)
        decoded = layers.BatchNormalization()(decoded)
        decoded = layers.Dense(self.input_dim, activation='sigmoid', name='decoded')(decoded)

        # Models
        autoencoder = models.Model(input_layer, decoded, name='autoencoder')
        encoder = models.Model(input_layer, encoded, name='encoder')

        return autoencoder, encoder

    def build_hybrid_model(self) -> keras.Model:
        """Build hybrid model combining CNN and LSTM"""
        logger.info("Building hybrid CNN-LSTM model")

        # Input
        input_layer = layers.Input(shape=(self.input_dim,))

        # CNN branch
        cnn_reshape = layers.Reshape((self.input_dim, 1))(input_layer)
        cnn_conv1 = layers.Conv1D(64, 3, activation='relu', padding='same')(cnn_reshape)
        cnn_pool1 = layers.MaxPooling1D(2)(cnn_conv1)
        cnn_conv2 = layers.Conv1D(32, 3, activation='relu', padding='same')(cnn_pool1)
        cnn_pool2 = layers.GlobalAveragePooling1D()(cnn_conv2)

        # LSTM branch
        lstm_reshape = layers.Reshape((min(10, self.input_dim), -1))(input_layer)
        lstm_layer = layers.LSTM(64, dropout=0.3)(lstm_reshape)

        # Combine branches
        combined = layers.concatenate([cnn_pool2, lstm_layer])
        combined = layers.Dense(64, activation='relu')(combined)
        combined = layers.BatchNormalization()(combined)
        combined = layers.Dropout(0.5)(combined)
        output = layers.Dense(1, activation='sigmoid', name='output')(combined)

        model = models.Model(input_layer, output, name='hybrid_cnn_lstm')
        return model

    def build_model(self, **kwargs) -> keras.Model:
        """Build model based on specified type"""
        logger.info(f"Building {self.model_type} model...")

        if self.model_type == 'dnn':
            self.model = self.build_dnn_model(**kwargs)
        elif self.model_type == 'cnn':
            self.model = self.build_cnn_model(**kwargs)
        elif self.model_type == 'lstm':
            self.model = self.build_lstm_model(**kwargs)
        elif self.model_type == 'autoencoder':
            self.model, self.encoder = self.build_autoencoder_model(**kwargs)
        elif self.model_type == 'hybrid':
            self.model = self.build_hybrid_model()
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")

        return self.model

    def compile_model(self, learning_rate: float = 0.001, metrics: List[str] = None):
        """Compile the model with optimizer and loss function"""
        if self.model is None:
            raise ValueError("Model not built. Call build_model() first.")

        if metrics is None:
            metrics = ['accuracy', 'precision', 'recall']

        try:
            # Try to use legacy optimizer for M1 Mac compatibility
            optimizer = tf.keras.optimizers.legacy.Adam(learning_rate=learning_rate)
        except AttributeError:
            # Fallback to regular Adam if legacy not available
            optimizer = tf.keras.optimizers.Adam(learning_rate=learning_rate)

        if self.model_type == 'autoencoder':
            loss = 'mse'
            metrics = ['mae']
        else:
            loss = 'binary_crossentropy'

        self.model.compile(
            optimizer=optimizer,
            loss=loss,
            metrics=metrics
        )

        logger.info(f"Model compiled with learning rate: {learning_rate}")

    def train_model(self, X_train: np.ndarray, y_train: np.ndarray,
                    X_val: np.ndarray = None, y_val: np.ndarray = None,
                    epochs: int = 100, batch_size: int = 128,
                    early_stopping: bool = True) -> Dict:
        """Train the model"""
        if self.model is None:
            raise ValueError("Model not built and compiled.")

        logger.info(f"Training model for {epochs} epochs...")

        # Prepare callbacks
        callback_list = []

        if early_stopping:
            early_stop = callbacks.EarlyStopping(
                monitor='val_loss' if X_val is not None else 'loss',
                patience=15,
                restore_best_weights=True,
                verbose=1
            )
            callback_list.append(early_stop)

        # Learning rate reduction
        lr_reduce = callbacks.ReduceLROnPlateau(
            monitor='val_loss' if X_val is not None else 'loss',
            factor=0.5,
            patience=10,
            min_lr=1e-7,
            verbose=1
        )
        callback_list.append(lr_reduce)

        # Model checkpoint
        checkpoint = callbacks.ModelCheckpoint(
            'best_ids_model.h5',
            monitor='val_loss' if X_val is not None else 'loss',
            save_best_only=True,
            verbose=1
        )
        callback_list.append(checkpoint)

        # Train model
        validation_data = (X_val, y_val) if X_val is not None and y_val is not None else None

        self.history = self.model.fit(
            X_train, y_train,
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callback_list,
            verbose=1
        )

        self.is_trained = True
        logger.info("Model training completed!")

        return self.history.history

    def evaluate_model(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """Evaluate model performance"""
        if not self.is_trained:
            raise ValueError("Model not trained. Call train_model() first.")

        logger.info("Evaluating model...")

        # Predictions
        y_pred_proba = self.model.predict(X_test)
        y_pred = (y_pred_proba > 0.5).astype(int).flatten()

        # Calculate metrics
        test_loss, test_accuracy = self.model.evaluate(X_test, y_test, verbose=0)[:2]

        # Classification report
        class_report = classification_report(y_test, y_pred, output_dict=True)

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)

        # ROC AUC
        roc_auc = roc_auc_score(y_test, y_pred_proba)

        results = {
            'test_loss': test_loss,
            'test_accuracy': test_accuracy,
            'roc_auc': roc_auc,
            'classification_report': class_report,
            'confusion_matrix': cm.tolist(),
            'predictions': y_pred.tolist(),
            'prediction_probabilities': y_pred_proba.flatten().tolist()
        }

        logger.info(f"Model evaluation completed - Accuracy: {test_accuracy:.4f}, ROC-AUC: {roc_auc:.4f}")

        return results

    def predict_batch(self, X: np.ndarray, threshold: float = 0.5) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions on a batch of data"""
        if not self.is_trained:
            raise ValueError("Model not trained.")

        probabilities = self.model.predict(X)
        predictions = (probabilities > threshold).astype(int).flatten()

        return predictions, probabilities.flatten()

    def save_model(self, filepath: str):
        """Save the trained model"""
        if self.model is None:
            raise ValueError("No model to save.")

        self.model.save(filepath)
        logger.info(f"Model saved to {filepath}")

    def load_model(self, filepath: str):
        """Load a trained model"""
        self.model = keras.models.load_model(filepath)
        self.is_trained = True
        logger.info(f"Model loaded from {filepath}")

    def get_model_summary(self) -> str:
        """Get model architecture summary"""
        if self.model is None:
            return "No model built."

        summary_list = []
        self.model.summary(print_fn=lambda x: summary_list.append(x))
        return '\n'.join(summary_list)


# Example usage and testing
if __name__ == "__main__":
    # Test with sample data
    logger.info("Testing Deep Learning IDS Model...")

    # Create sample data
    np.random.seed(42)
    n_samples = 1000
    n_features = 20

    X_train = np.random.randn(n_samples, n_features)
    y_train = np.random.randint(0, 2, n_samples)

    X_test = np.random.randn(200, n_features)
    y_test = np.random.randint(0, 2, 200)

    # Test different model types
    model_types = ['dnn', 'cnn', 'lstm', 'hybrid']

    for model_type in model_types:
        try:
            print(f"\n=== Testing {model_type.upper()} Model ===")

            # Initialize model
            ids_model = DeepIDSModel(input_dim=n_features, model_type=model_type)

            # Build and compile model
            ids_model.build_model()
            ids_model.compile_model(learning_rate=0.001)

            print(f"Model architecture:")
            print(ids_model.get_model_summary())

            # Train model (reduced epochs for testing)
            history = ids_model.train_model(
                X_train, y_train,
                X_test, y_test,
                epochs=5,  # Reduced for testing
                batch_size=32,
                early_stopping=False
            )

            # Evaluate model
            results = ids_model.evaluate_model(X_test, y_test)

            print(f"Test Accuracy: {results['test_accuracy']:.4f}")
            print(f"ROC-AUC: {results['roc_auc']:.4f}")

            # Test predictions
            predictions, probabilities = ids_model.predict_batch(X_test[:10])
            print(f"Sample predictions: {predictions[:5]}")
            print(f"Sample probabilities: {probabilities[:5]}")

        except Exception as e:
            print(f"Error testing {model_type} model: {str(e)}")

    print("\nDeep Learning IDS Model testing completed!")
