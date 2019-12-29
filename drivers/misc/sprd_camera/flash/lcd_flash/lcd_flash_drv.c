/*
 * Copyright (C) 2015-2016 Spreadtrum Communications Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/errno.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/vmalloc.h>
#include <linux/sprd_otp.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/unistd.h>

#include "flash_drv.h"
#include "lcd_flash_reg.h"
#define FLASH_GPIO_MAX 3

/* Structure Definitions */
#define BACKLIGHT_FILE "/sys/class/backlight/sprd_backlight/brightness"
#define FLIP_FILE "/sys/class/display/dispc0/disable_flip"
#define TIEMOUT_FILE "/sys/class/display/dispc0/disable_timeout"
#define BGCOLOR_FILE "/sys/class/display/dispc0/bg_color"
#define DECIMAL_TYPE 10
#define HEXADECIMAL_TYPE 16
struct flash_driver_data {
	struct regmap *reg_map;
	spinlock_t slock;
	int gpio_tab[SPRD_FLASH_NUM_MAX][FLASH_GPIO_MAX];
	void *priv;
	unsigned int  lcd_reg_base;
	int is_highlight;
};

/* Static Variables Definitions */

static const char *const flash_gpio_names[SPRD_FLASH_NUM_MAX] = {
	"flash0-gpios",
	"flash1-gpios",
	"flash2-gpios",
};

/* Internal Function Implementation */
#if 0
static irqreturn_t flash_interrupt_handler(int irq, void *priv)
{
	int ret = 0;
	unsigned int status;
	unsigned long flag;
	irqreturn_t irq_ret = 0;
	struct flash_driver_data *drv_data;

	if (!priv)
		return IRQ_NONE;

	drv_data = (struct flash_driver_data *)priv;

	spin_lock_irqsave(&drv_data->slock, flag);

	ret = regmap_read(drv_data->reg_map, FLASH_IRQ_INT, &status);
	if (ret) {
		spin_unlock_irqrestore(&drv_data->slock, flag);
		return IRQ_NONE;
	}

	status &= FLASH_IRQ_BIT_MASK;
	pr_info("irq status 0x%x\n", status);

	regmap_update_bits(drv_data->reg_map,
			   FLASH_IRQ_CLR,
			   FLASH_IRQ_BIT_MASK, FLASH_IRQ_BIT_MASK);

	if (status)
		irq_ret = IRQ_HANDLED;
	else
		irq_ret = IRQ_NONE;

	spin_unlock_irqrestore(&drv_data->slock, flag);

	return irq_ret;
}
#endif

static void sprd_flash_lcd_bk_init(struct flash_driver_data *drv_data)
{
	/* flash ctrl */
}

static int sprd_flash_lcd_flip_file_ops(const char *file_name,
					unsigned int flip, int base_type)
{
	struct file *fd;
	mm_segment_t fs;
	char buf[16] = {0};
	size_t len = 0;
	ssize_t ret;

	fd = filp_open(file_name, O_RDWR, 0644);
	if (IS_ERR(fd)) {
		pr_err("%s open file data error %ld\n",
			__func__, PTR_ERR(fd));
		return PTR_ERR(fd);
	}

	fs = get_fs();
	set_fs(KERNEL_DS);

	if (base_type == 16)
		len = snprintf(buf, sizeof(buf), "%x\n", flip);
	else
		len = snprintf(buf, sizeof(buf), "%d\n", flip);

	ret = vfs_write(fd, buf, len, &fd->f_pos);
	fd->f_pos = 0;

	filp_close(fd, NULL);

	set_fs(fs);

	pr_info("flip 0x%x\n", flip);

	return 0;
}

#define BITSINDEX(b, o)  ((b) * 16 + (o))

static void sprd_flash_cal(void *drvd)
{
}

/* API Function Implementation */

static int sprd_flash_lcd_open_torch(void *drvd, uint8_t idx)
{
	struct flash_driver_data *drv_data = (struct flash_driver_data *)drvd;

	if (!drv_data)
		return -EFAULT;


	return 0;
}

static int sprd_flash_lcd_close_torch(void *drvd, uint8_t idx)
{
	struct flash_driver_data *drv_data = (struct flash_driver_data *)drvd;

	if (!drv_data)
		return -EFAULT;


	return 0;
}

static int sprd_flash_lcd_open_preflash(void *drvd, uint8_t idx)
{
	struct flash_driver_data *drv_data = (struct flash_driver_data *)drvd;

	if (!drv_data)
		return -EFAULT;

	pr_info("sprd_flash_lcd_open_preflash\n");

	sprd_flash_lcd_flip_file_ops(BGCOLOR_FILE, 0xffffff, HEXADECIMAL_TYPE);
	sprd_flash_lcd_flip_file_ops(TIEMOUT_FILE, 240, DECIMAL_TYPE);

	sprd_flash_lcd_flip_file_ops(BACKLIGHT_FILE, 0xff, HEXADECIMAL_TYPE);

	return 0;
}

static int sprd_flash_lcd_close_preflash(void *drvd, uint8_t idx)
{
	struct flash_driver_data *drv_data = (struct flash_driver_data *)drvd;

	if (!drv_data)
		return -EFAULT;

	return 0;
}

static int sprd_flash_lcd_open_highlight(void *drvd, uint8_t idx)
{
	int ret = 0;
	struct flash_driver_data *drv_data = (struct flash_driver_data *)drvd;

	if (!drv_data)
		return -EFAULT;

	return ret;
}

static int sprd_flash_lcd_close_highlight(void *drvd, uint8_t idx)
{
	int ret = 0;
	struct flash_driver_data *drv_data = (struct flash_driver_data *)drvd;

	if (!drv_data)
		return -EFAULT;

	if (drv_data->is_highlight) {
		sprd_flash_lcd_flip_file_ops(BACKLIGHT_FILE, 0x55,
						HEXADECIMAL_TYPE);
		sprd_flash_lcd_flip_file_ops(FLIP_FILE, 0, HEXADECIMAL_TYPE);
		drv_data->is_highlight = 0;
	}
	pr_info("sprd_flash_lcd_close_highlight\n");

	return ret;
}

static int sprd_flash_lcd_cfg_value_preflash(void *drvd, uint8_t idx,
					  struct sprd_flash_element *element)
{
	struct flash_driver_data *drv_data = (struct flash_driver_data *)drvd;

	if (!drv_data)
		return -EFAULT;

	drv_data->is_highlight = 0;

	return 0;
}

static int sprd_flash_lcd_cfg_value_highlight(void *drvd, uint8_t idx,
					   struct sprd_flash_element *element)
{
	struct flash_driver_data *drv_data = (struct flash_driver_data *)drvd;

	if (!drv_data)
		return -EFAULT;

	drv_data->is_highlight = 1;

	return 0;
}

static const struct sprd_flash_driver_ops flash_lcd_ops = {
	.open_torch = sprd_flash_lcd_open_torch,
	.close_torch = sprd_flash_lcd_close_torch,
	.open_preflash = sprd_flash_lcd_open_preflash,
	.close_preflash = sprd_flash_lcd_close_preflash,
	.open_highlight = sprd_flash_lcd_open_highlight,
	.close_highlight = sprd_flash_lcd_close_highlight,
	.cfg_value_preflash = sprd_flash_lcd_cfg_value_preflash,
	.cfg_value_highlight = sprd_flash_lcd_cfg_value_highlight,
};

static const struct of_device_id lcd_flash_of_match[] = {
	{ .compatible = "sprd,lcd-flash", .data = &flash_lcd_ops },
	{},
};

static int sprd_flash_lcd_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct flash_driver_data *drv_data;

	if (IS_ERR(pdev))
		return -EINVAL;

	drv_data = devm_kzalloc(&pdev->dev, sizeof(*drv_data), GFP_KERNEL);
	if (!drv_data)
		return -ENOMEM;

	pdev->dev.platform_data = (void *)drv_data;

	drv_data->reg_map = dev_get_regmap(pdev->dev.parent, NULL);
	if (IS_ERR(drv_data->reg_map)) {
		pr_err("failed to regmap for flash\n");
		ret = PTR_ERR(drv_data->reg_map);
		goto exit;
	}

	ret = sprd_flash_register(&flash_lcd_ops, drv_data,
							SPRD_FLASH_FRONT);
	if (ret < 0)
		goto exit;
	spin_lock_init(&drv_data->slock);

	sprd_flash_lcd_bk_init(drv_data);

	sprd_flash_cal(drv_data);


exit:

	return ret;
}

static int sprd_flash_lcd_remove(struct platform_device *pdev)
{
	return 0;
}

static struct platform_driver sprd_flash_lcd_drvier = {
	.probe = sprd_flash_lcd_probe,
	.remove = sprd_flash_lcd_remove,
	.driver = {
		.name = "lcd-flash",
		.of_match_table = of_match_ptr(lcd_flash_of_match),
	},
};

static int __init sprd_flash_lcd_init(void)
{
	return platform_driver_register(&sprd_flash_lcd_drvier);
}

static void __exit sprd_flash_lcd_exit(void)
{
	platform_driver_unregister(&sprd_flash_lcd_drvier);
}

late_initcall(sprd_flash_lcd_init);

module_exit(sprd_flash_lcd_exit);
