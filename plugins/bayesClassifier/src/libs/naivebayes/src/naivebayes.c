/*
 * naivebayes.c
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

#include "naivebayes.h"


/* Model functions */

model_t* model_init(uint32_t num_probs) {
    model_t * const model = calloc(1, sizeof(*model));

    model->num_probs = num_probs;
    if (num_probs > 0) {
        model->probs = calloc(num_probs, sizeof(prob_t));
    }

    return model;
}


static void model_destroy(model_t *model) {
    if (model->label) {
        free(model->label);
        model->label = NULL;
    }

    if (model->probs) {
        free(model->probs);
        model->probs = NULL;
    }

    // model is owned by the classifier...
    //free(model);
}


static uint32_t add_dataset(model_t *mdl, const uint64_t *dataset, uint64_t dataset_len) {
    uint32_t num_unknown = 0;
    for (size_t i = 0; i < dataset_len; i++) {
        const uint64_t key = dataset[i];
        prob_t *prob = NULL;

        // Check if key exists:
        const uint32_t num_probs = mdl->num_probs;
        for (uint_fast32_t j = 0; j < num_probs; j++) {
            if (mdl->probs[j].key == key) {
                prob = &mdl->probs[j];
                break;
            }
        }

        if (prob) {
            prob->count++;
        } else {
            // Key does not exist
            num_unknown++;
            mdl->num_probs++;
            // TODO: find better way
            mdl->probs = realloc(mdl->probs, sizeof(prob_t) * mdl->num_probs);
            prob = &mdl->probs[mdl->num_probs-1];
            prob->key = key;
            prob->count = 1;
        }

        mdl->total_count++;
    }

    mdl->num_samples++;

    return num_unknown;
}


static int model_train(model_t *mdl, uint32_t total_samples, uint32_t total_probs, double smoothing) {
    mdl->prior = log((double) mdl->num_samples / (double) total_samples);
    mdl->default_prob = smoothing / ( \
                     (double) mdl->num_probs + \
                     smoothing * (double) total_probs);
    return 0;
}


static double get_probability(model_t *mdl, uint64_t key) {
    double prob = 0;
    const uint_fast32_t num_probs = mdl->num_probs;
    for (uint_fast32_t i = 0; i < num_probs; i++) {
        if (mdl->probs[i].key == key) {
            prob = (double) mdl->probs[i].count / (double) mdl->total_count;
            break;
        }
    }

    // Check if prob is NaN with prob != prob
    if (prob <= 0 || prob != prob) {
        prob = mdl->default_prob;
    }

    return log(prob);
}


int score_dataset(model_t *mdl, const uint64_t *dataset, uint64_t dataset_len) {
    // Reset model
    mdl->likelihood = 0;
    mdl->posteriori = 0;

    for (uint_fast32_t i = 0; i < dataset_len; i++) {
        const uint64_t key = dataset[i];
        mdl->likelihood += get_probability(mdl, key);
    }

    mdl->posteriori = mdl->likelihood + mdl->prior;

    return 0;
}


model_t* model_from_json(const char *encoded UNUSED) {
    // TODO
    NB_ERR("%s not implemented yet", __func__);
    exit(1);
}


json_t* model_to_json(model_t *mdl UNUSED) {
    // TODO
    NB_ERR("%s not implemented yet", __func__);
    exit(1);
}


/* Classifier functions */

classifier_t* classifier_init(uint32_t num_models) {
    classifier_t * const classifier = calloc(1, sizeof(classifier_t));
    classifier->smoothing = DEFAULT_SMOOTHING;

    classifier->num_models = num_models;
    if (num_models > 0) {
        classifier->models = calloc(num_models, sizeof(model_t));
    }

    return classifier;
}


int classifier_add_model(classifier_t *cls, const char *mdl_label) {
    // Check if model with label mdl_label exists
    const uint_fast32_t num_models = cls->num_models;
    for (uint_fast32_t i = 0; i < num_models; i++) {
        if (strncmp(mdl_label, cls->models[i].label, MAX_LABEL_SIZE) == 0) {
            NB_DBG("Model with label: %s, already exists!", mdl_label);
            return 1;
        }
    }

    const size_t label_len = strlen(mdl_label);
    if (label_len > MAX_LABEL_SIZE) {
        NB_DBG("Label %s is too long", mdl_label);
        return 1;
    }

    cls->num_models++;
    cls->models = realloc(cls->models, sizeof(model_t) * (num_models+1));

    model_t * const mdl = &cls->models[num_models];
    memset(mdl, 0, sizeof(*mdl));

    mdl->label = calloc(label_len+1, sizeof(char));
    strncpy(mdl->label, mdl_label, label_len+1);

    return 0;
}


void classifier_destroy(classifier_t *cls) {
    const uint_fast32_t num_models = cls->num_models;
    for (uint_fast32_t i = 0; i < num_models; i++) {
        model_destroy(&cls->models[i]);
    }
    free(cls->models);
    free(cls);
}


int classifier_score_dataset(classifier_t* cls, const uint64_t* dataset, uint64_t dataset_len) {
    int bm_idx = -1;
    double bm_posterior = -DBL_MAX;

    const uint_fast32_t num_models = cls->num_models;
    for (uint_fast32_t i = 0; i < num_models; i++) {
        if (score_dataset(&cls->models[i], dataset, dataset_len) == 1) {
            NB_DBG("Cannot calculate score for model %" PRIuFAST32, i);
            continue;
        }

        if (bm_posterior < cls->models[i].posteriori) {
            bm_idx = i;
            bm_posterior = cls->models[i].posteriori;
        } else if (cls->models[bm_idx].posteriori == cls->models[i].posteriori) {
            // TODO: handle this case!
            NB_DBG("model %" PRIuFAST32 " and actual best match (model %i) same posteriori", i, bm_idx);
            bm_idx = -1;
        }
    }

    if (bm_idx != -1) {
        cls->total_classified++;
        cls->models[bm_idx].num_classified++;
    }

    return bm_idx;
}


int classifier_train(classifier_t *cls) {
    const double smoothing = cls->smoothing;
    const uint_fast32_t total_probs = cls->total_probs;
    const uint_fast32_t total_samples = cls->total_samples;

    const uint_fast32_t num_models = cls->num_models;
    for (uint_fast32_t i = 0; i < num_models; i++) {
        model_train(&cls->models[i], total_samples, total_probs, smoothing);
    }

    return 0;
}


int classifier_add_dataset(classifier_t *cls, const char *mdl_label, const uint64_t *dataset, uint64_t dataset_len) {
    const uint_fast32_t num_models = cls->num_models;
    for (uint_fast32_t i = 0; i < num_models; i++) {
        // Find model
        if (strncmp(mdl_label, cls->models[i].label, MAX_LABEL_SIZE) == 0) {
            cls->total_samples++;
            cls->total_probs += add_dataset(&cls->models[i], dataset, dataset_len);
            return 0;
        }
    }

    NB_DBG("Model with label: %s is not part of the classifier", mdl_label);

    return 1;
}


classifier_t* classifier_from_json(const char *encoded) {
    json_error_t error;

    json_t * const root = json_loads(encoded, 0, &error);
    if (UNLIKELY(!root)) {
        NB_ERR("Error on line %d: %s\n", error.line, error.text);
        return NULL;
    }

    const json_t * const cls_settings = json_object_get(root, "classifier");

    if (UNLIKELY(!json_is_object(cls_settings))) {
        json_decref(root);
        NB_DBG("Classifier settings field is not of type json object!");
        return NULL;
    }

    const json_t * const models = json_object_get(root, "models");

    if (UNLIKELY(!json_is_array(models))) {
        json_decref(root);
        NB_DBG("Classifier models field is not of type json array!");
        return NULL;
    }

    const uint32_t num_models = json_array_size(models);
    classifier_t* classifier = classifier_init(num_models);

    json_t *val = json_object_get(cls_settings, "smoothing");
    if (!json_is_real(val)) {
        json_decref(root);
        NB_DBG("Classifier smoothing field is not of type real");
        classifier_destroy(classifier);
        return NULL;
    }

    classifier->smoothing = json_real_value(val);

    val = json_object_get(cls_settings, "total_of_samples");
    if (!json_is_integer(val)) {
        json_decref(root);
        NB_DBG("Classifier total_samples field is not of type integer");
        classifier_destroy(classifier);
        return NULL;
    }

    classifier->total_samples = json_integer_value(val);

    classifier->total_classified = 0;

    for (uint_fast32_t i = 0; i < num_models; i++) {
        json_t *model = json_array_get(models, i);

        if (!json_is_object(model)) {
            json_decref(root);
            NB_DBG("Model: % " PRIuFAST32 " is not of type object", i);
            classifier_destroy(classifier);
            return NULL;
        }

        const json_t * const mdl_settings = json_object_get(model, "settings");

        if (!json_is_object(mdl_settings)) {
            json_decref(root);
            NB_DBG("Model: %" PRIuFAST32 " settings is not of type object", i);
            classifier_destroy(classifier);
            return NULL;
        }

        val = json_object_get(mdl_settings, "label");

        if (!json_is_string(val)) {
            json_decref(root);
            NB_DBG("Model: %" PRIuFAST32 " label is not of type string", i);
            classifier_destroy(classifier);
            return NULL;
        }

        model_t* mdl = &classifier->models[i];

        const size_t label_len = json_string_length(val);
        if (label_len > MAX_LABEL_SIZE) {
            json_decref(root);
            NB_DBG("Model: %" PRIuFAST32 " label is too long", i);
            classifier_destroy(classifier);
            return NULL;
        }

        const char* label_value = json_string_value(val);
        mdl->label = calloc(label_len+1, sizeof(char));
        strncpy(mdl->label, label_value, label_len+1);
        mdl->label[label_len] = '\0';

        val = json_object_get(mdl_settings, "total_count");
        if (!json_is_integer(val)) {
            json_decref(root);
            NB_DBG("Model: %" PRIuFAST32 " total_count is not of type integer ", i);
            classifier_destroy(classifier);
            return NULL;
        }

        mdl->total_count = json_integer_value(val);

        val = json_object_get(mdl_settings, "number_of_samples");
        if (!json_is_integer(val)) {
            json_decref(root);
            NB_DBG("Model: %" PRIuFAST32 " number_of_samples is not of type integer", i);
            classifier_destroy(classifier);
            return NULL;
        }

        mdl->num_samples = json_integer_value(val);
        mdl->num_classified = 0;

        json_t *probs = json_object_get(model, "probabilities");
        if (!json_is_array(probs)) {
            json_decref(root);
            NB_DBG("Model: %" PRIuFAST32 " Probabilities is not of type array", i);
            classifier_destroy(classifier);
            return NULL;
        }

        const uint32_t num_probs = json_array_size(probs);
        mdl->num_probs = num_probs;
        mdl->probs = calloc(num_probs, sizeof(prob_t));

        for (size_t j = 0; j < num_probs; j++) {
            json_t * const prob = json_array_get(probs, j);
            if (!json_is_object(prob)) {
                json_decref(root);
                NB_DBG("Model: %" PRIuFAST32 " Probability: %" PRIuFAST32 " is not of type object", i, j);
                classifier_destroy(classifier);
                return NULL;
            }

            val = json_object_get(prob, "key");
            if (!json_is_integer(val)) {
                json_decref(root);
                NB_DBG("Model: %" PRIuFAST32 " Probability: %" PRIuFAST32 " key is not of type integer", i, j);
                classifier_destroy(classifier);
                return NULL;
            }

            mdl->probs[j].key = json_integer_value(val);

            val = json_object_get(prob, "count");
            if (!json_is_integer(val)) {
                json_decref(root);
                NB_DBG("Model: %" PRIuFAST32 " Probability: %" PRIuFAST32 " count is not of type integer", i, j);
                classifier_destroy(classifier);
                return NULL;
            }

            mdl->probs[j].count = json_integer_value(val);
            classifier->total_probs++;
        }
    }

    json_decref(root);

    classifier_train(classifier);

    return classifier;
}



// Returned value MUST be free'd with json_decref()
// TODO: error handling...
json_t* classifier_to_json(classifier_t* cls) {

    json_t * const root = json_object();
    if (UNLIKELY(!root)) {
        NB_DBG("Could not create json object for classifier");
        return NULL;
    }

    // Classifier settings
    json_t * const cls_settings = json_object();
    if (UNLIKELY(!cls_settings)) {
        NB_DBG("Could not create json object for classifier settings");
        json_decref(root);
        return NULL;
    }

    json_object_set_new(root, "classifier", cls_settings);

    json_t *val = json_real(cls->smoothing);
    if (UNLIKELY(!val)) {
        NB_DBG("Could not get classifier smoothing");
        json_decref(root);
        return NULL;
    }

    json_object_set_new(cls_settings, "smoothing", val);

    val = json_integer(cls->total_samples);
    if (UNLIKELY(!val)) {
        NB_DBG("Could not get classifier total_samples");
        json_decref(root);
        return NULL;
    }

    json_object_set_new(cls_settings, "total_of_samples", val);

    // Models
    json_t * const models = json_array();
    if (UNLIKELY(!models)) {
        NB_DBG("Could not create json array for models");
        json_decref(root);
        return NULL;
    }

    json_object_set_new(root, "models", models);

    const uint_fast32_t num_models = cls->num_models;
    for (uint_fast32_t i = 0; i < num_models; i++) {
        json_t * const json_model = json_object();
        if (UNLIKELY(!json_model)) {
            NB_DBG("Could not create json object for model %" PRIuFAST32, i);
            json_decref(root);
            return NULL;
        }

        json_array_append_new(models, json_model);

        // Model setting
        json_t * const mdl_settings = json_object();
        if (UNLIKELY(!mdl_settings)) {
            NB_DBG("Could not create json object for model settings, model: %" PRIuFAST32, i);
            json_decref(root);
            return NULL;
        }

        const model_t model = cls->models[i];

        val = json_integer(model.num_samples);
        if (UNLIKELY(!val)) {
            NB_DBG("Could not get num_samples, model: %" PRIuFAST32, i);
            json_decref(root);
            return NULL;
        }

        json_object_set_new(mdl_settings, "number_of_samples", val);

        val = json_string(model.label);
        if (UNLIKELY(!val)) {
            NB_DBG("Could not get label, model: %" PRIuFAST32, i);
            json_decref(root);
            return NULL;
        }

        json_object_set_new(mdl_settings, "label", val);

        val = json_integer(model.total_count);
        if (UNLIKELY(!val)) {
            NB_DBG("Could not get total_count, model: %" PRIuFAST32, i);
            json_decref(root);
            return NULL;
        }

        json_object_set_new(mdl_settings, "total_count", val);

        json_object_set_new(json_model, "settings", mdl_settings);

        // Model probabilities

        json_t * const probs = json_array();
        if (UNLIKELY(!probs)) {
            NB_DBG("Could not create json object for probabilities, model: %" PRIuFAST32, i);
            json_decref(root);
            return NULL;
        }

        json_object_set_new(json_model, "probabilities", probs);

        const uint_fast32_t num_probs = model.num_probs;
        for (uint_fast32_t j = 0; j < num_probs; j++) {
            json_t * const act_json = json_object();
            if (UNLIKELY(!act_json)) {
                NB_DBG("Could not create json object for probability %" PRIuFAST32 ", model: %" PRIuFAST32, j, i);
                json_decref(root);
                return NULL;
            }

            json_array_append_new(probs, act_json);

            const prob_t prob = model.probs[j];

            val = json_integer(prob.key);
            if (UNLIKELY(!val)) {
                NB_DBG("Could not get key, probability %" PRIuFAST32 ", model: %" PRIuFAST32, j, i);
                json_decref(root);
                return NULL;
            }

            json_object_set_new(act_json, "key", val);

            val = json_integer(prob.count);
            if (UNLIKELY(!val)) {
                NB_DBG("Could not get count, probability %" PRIuFAST32 ", model: %" PRIuFAST32, j, i);
                json_decref(root);
                return NULL;
            }

            json_object_set_new(act_json, "count", val);
        }
    }

    return root;
}
