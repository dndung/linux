// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018 Maxime Jourdan <maxi.jourdan@wanadoo.fr>
 * Copyright (C) 2016 BayLibre, SAS
 * Author: Neil Armstrong <narmstrong@baylibre.com>
 * Copyright (C) 2015 Amlogic, Inc. All rights reserved.
 * Copyright (C) 2014 Endless Mobile
 */

#include <linux/kernel.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/soc/amlogic/meson-canvas.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/io.h>

#define NUM_CANVAS 256

/* DMC Registers */
#define DMC_CAV_LUT_DATAL	0x48 /* 0x12 offset in data sheet */
	#define CANVAS_WIDTH_LBIT	29
	#define CANVAS_WIDTH_LWID       3
#define DMC_CAV_LUT_DATAH	0x4c /* 0x13 offset in data sheet */
	#define CANVAS_WIDTH_HBIT       0
	#define CANVAS_HEIGHT_BIT       9
	#define CANVAS_BLKMODE_BIT      24
#define DMC_CAV_LUT_ADDR	0x50 /* 0x14 offset in data sheet */
	#define CANVAS_LUT_WR_EN        (0x2 << 8)
	#define CANVAS_LUT_RD_EN        (0x1 << 8)

struct meson_canvas {
	struct device *dev;
	struct regmap *regmap_dmc;
	spinlock_t lock; /* canvas device lock */
	u8 used[NUM_CANVAS];
};

struct meson_canvas *meson_canvas_get(struct device *dev)
{
	struct device_node *canvas_node;
	struct platform_device *canvas_pdev;
	struct meson_canvas *canvas;

	canvas_node = of_parse_phandle(dev->of_node, "amlogic,canvas", 0);
	if (!canvas_node)
		return ERR_PTR(-ENODEV);

	canvas_pdev = of_find_device_by_node(canvas_node);
	if (!canvas_pdev) {
		dev_err(dev, "Unable to find canvas pdev\n");
		return ERR_PTR(-ENODEV);
	}

	canvas = dev_get_drvdata(&canvas_pdev->dev);
	if (!canvas)
		return ERR_PTR(-ENODEV);

	return canvas;
}
EXPORT_SYMBOL_GPL(meson_canvas_get);

int meson_canvas_setup(struct meson_canvas *canvas, u8 canvas_index,
		       u32 addr, u32 stride, u32 height,
		       unsigned int wrap,
		       unsigned int blkmode,
		       unsigned int endian)
{
	struct regmap *regmap = canvas->regmap_dmc;
	unsigned long flags;
	u32 val;

	spin_lock_irqsave(&canvas->lock, flags);
	if (!canvas->used[canvas_index]) {
		dev_err(canvas->dev,
			"Trying to setup non allocated canvas %u\n",
			canvas_index);
		spin_unlock_irqrestore(&canvas->lock, flags);
		return -EINVAL;
	}

	regmap_write(regmap, DMC_CAV_LUT_DATAL,
		     ((addr + 7) >> 3) |
		     (((stride + 7) >> 3) << CANVAS_WIDTH_LBIT));

	regmap_write(regmap, DMC_CAV_LUT_DATAH,
		     ((((stride + 7) >> 3) >> CANVAS_WIDTH_LWID) <<
						CANVAS_WIDTH_HBIT) |
		     (height << CANVAS_HEIGHT_BIT) |
		     (wrap << 22) |
		     (blkmode << CANVAS_BLKMODE_BIT) |
		     (endian << 26));

	regmap_write(regmap, DMC_CAV_LUT_ADDR,
		     CANVAS_LUT_WR_EN | canvas_index);

	/* Force a read-back to make sure everything is flushed. */
	regmap_read(regmap, DMC_CAV_LUT_DATAH, &val);
	spin_unlock_irqrestore(&canvas->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(meson_canvas_setup);

int meson_canvas_alloc(struct meson_canvas *canvas, u8 *canvas_index)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&canvas->lock, flags);
	for (i = 0; i < NUM_CANVAS; ++i) {
		if (!canvas->used[i]) {
			canvas->used[i] = 1;
			spin_unlock_irqrestore(&canvas->lock, flags);
			*canvas_index = i;
			return 0;
		}
	}
	spin_unlock_irqrestore(&canvas->lock, flags);

	dev_err(canvas->dev, "No more canvas available\n");
	return -ENODEV;
}
EXPORT_SYMBOL_GPL(meson_canvas_alloc);

int meson_canvas_free(struct meson_canvas *canvas, u8 canvas_index)
{
	unsigned long flags;

	spin_lock_irqsave(&canvas->lock, flags);
	if (!canvas->used[canvas_index]) {
		dev_err(canvas->dev,
			"Trying to free unused canvas %u\n", canvas_index);
		spin_unlock_irqrestore(&canvas->lock, flags);
		return -EINVAL;
	}
	canvas->used[canvas_index] = 0;
	spin_unlock_irqrestore(&canvas->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(meson_canvas_free);

static int meson_canvas_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct meson_canvas *canvas;

	canvas = devm_kzalloc(dev, sizeof(*canvas), GFP_KERNEL);
	if (!canvas)
		return -ENOMEM;

	canvas->regmap_dmc =
		syscon_node_to_regmap(of_get_parent(dev->of_node));
	if (IS_ERR(canvas->regmap_dmc)) {
		dev_err(dev, "failed to get DMC regmap\n");
		return PTR_ERR(canvas->regmap_dmc);
	}

	canvas->dev = dev;
	spin_lock_init(&canvas->lock);
	dev_set_drvdata(dev, canvas);

	return 0;
}

static const struct of_device_id canvas_dt_match[] = {
	{ .compatible = "amlogic,canvas" },
	{}
};
MODULE_DEVICE_TABLE(of, canvas_dt_match);

static struct platform_driver meson_canvas_driver = {
	.probe = meson_canvas_probe,
	.driver = {
		.name = "amlogic-canvas",
		.of_match_table = canvas_dt_match,
	},
};
module_platform_driver(meson_canvas_driver);

MODULE_DESCRIPTION("Amlogic Canvas driver");
MODULE_AUTHOR("Maxime Jourdan <maxi.jourdan@wanadoo.fr>");
MODULE_LICENSE("GPL");
