// ML Engine for phishing detection
import * as tf from '@tensorflow/tfjs';

class MLEngine {
    constructor() {
        this.model = null;
        this.initialized = false;
    }

    async initialize() {
        // Initialize the model
        this.model = tf.sequential({
            layers: [
                tf.layers.dense({ inputShape: [100], units: 64, activation: 'relu' }),
                tf.layers.dense({ units: 32, activation: 'relu' }),
                tf.layers.dense({ units: 1, activation: 'sigmoid' })
            ]
        });

        this.model.compile({
            optimizer: tf.train.adam(0.001),
            loss: 'binaryCrossentropy',
            metrics: ['accuracy']
        });

        this.initialized = true;
    }

    async train(data, labels) {
        if (!this.initialized) await this.initialize();
        
        const xs = tf.tensor2d(data);
        const ys = tf.tensor2d(labels);

        return await this.model.fit(xs, ys, {
            epochs: 10,
            validationSplit: 0.2,
            callbacks: {
                onEpochEnd: (epoch, logs) => {
                    console.log(`Epoch ${epoch}: loss = ${logs.loss.toFixed(4)}`);
                }
            }
        });
    }

    async predict(features) {
        if (!this.initialized) await this.initialize();
        
        const inputTensor = tf.tensor2d([features]);
        const prediction = await this.model.predict(inputTensor);
        return prediction.dataSync()[0];
    }
}

export const mlEngine = new MLEngine(); 