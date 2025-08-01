/*
 * naivebayes.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef NAIVE_BAYES_H
#define NAIVE_BAYES_H

// Includes

#include <float.h>
#include <jansson.h>
#include <math.h>
#include <stdint.h>
#include <string.h>


// Defines

#define DEBUG_ACTIVE 0

#define DEFAULT_SMOOTHING 1.0
#define MAX_LABEL_SIZE    256

#if DEBUG_ACTIVE == 0
#define NB_DBG(format, args...)
#else
#define NB_DBG(format, args...) printf(format "\n", ##args)
#endif

#define NB_ERR(format, args...) fprintf(stderr, format, ##args)

// Hints the compiler that the expression is likely to evaluate to a true value
#define LIKELY(x) __builtin_expect ((x), 1)

// Hints the compiler that the expression is unlikely to evaluate to a true value
#define UNLIKELY(x) __builtin_expect ((x), 0)

#define UNUSED __attribute__((__unused__))


// Structures

typedef struct {
    uint64_t key;
    uint64_t count;
} prob_t;

// Discrete Bayes model
typedef struct {
    double prior;            // P(Mdl)
    double likelihood;       // P(Mdl | Flow)
    double posteriori;       // P(Flow | Mdl)
    uint32_t num_samples;    // Numer of samples used for training
    uint32_t num_classified; // Number of classified samples used for
                             // re-estimate prior
    uint32_t num_probs;      // Number of probabilities
    prob_t*  probs;          // Probabilities
    uint64_t total_count;    // Total count of probabilities
    double default_prob;     // If a probability of 0 occurs, return
                             // default_prob instead
    char *label;             // Name of model
} model_t;

// Bayes classifier
typedef struct {
    uint32_t  total_classified;
    double    smoothing;
    uint32_t  total_samples;
    uint32_t  total_probs;
    uint32_t  num_models;
    model_t  *models;
} classifier_t;


// Functions

classifier_t* classifier_init(uint32_t num_models);
void classifier_destroy(classifier_t *cls);

int classifier_add_model(classifier_t *cls, const char *mdl_label);
int classifier_add_dataset(classifier_t *cls, const char *mdl_label, const uint64_t *dataset, uint64_t dataset_len);

int classifier_train(classifier_t *cls);

int classifier_score_dataset(classifier_t *cls, const uint64_t *dataset, uint64_t dataset_len);

classifier_t* classifier_from_json(const char *encoded);
json_t* classifier_to_json(classifier_t *cls);

#endif // NAIVE_BAYES_H
