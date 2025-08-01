/*
 * bayesClassifier.h
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

#ifndef BAYES_CLASSIFIER_H
#define BAYES_CLASSIFIER_H

/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define BAYES_CFG           "bayes_config.json" // Bayes config file
                                                // (refer to ../bayes_config.json)
#define BAYES_UNKNOWN       "unknown"           // Default class name
#define BAYES_MIN_POST_PROB 0.0001              // Minimum post-probability
#define BAYES_MIN_NUM_PKT   1                   // Minimum amount of packets per flow

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*     No env / runtime configuration flags available for bayesClassifier     */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */

#endif // BAYES_CLASSIFIER_H
